// Package notify fans events out to a tenant's notification channels through
// a retrying outbox: producers Emit, a dispatcher sends.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"freelocker/internal/server/config"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type Event struct {
	Kind     string         `json:"kind"`
	TenantID uuid.UUID      `json:"tenant_id"`
	Title    string         `json:"title"`
	Body     string         `json:"body"`
	Detail   map[string]any `json:"detail"`
	At       time.Time      `json:"at"`
}

// Emitter is what producers depend on. Emit never returns an error: a
// notification failure must not fail the thing being notified about.
type Emitter interface {
	Emit(ctx context.Context, e Event)
}

// Nop is the Emitter for tests and unconfigured servers.
type Nop struct{}

func (Nop) Emit(context.Context, Event) {}

const (
	// Invariant: ClaimLease must exceed ClaimBatch x the slowest per-send
	// timeout (webhooks 10s, SMTP up to a 30s connection deadline), because a
	// claimed batch is sent serially. If the lease expired mid-batch another
	// instance would re-claim rows still in flight and send them twice.
	ClaimLease  = 10 * time.Minute
	ClaimBatch  = 10
	MaxAttempts = 5
	errNoSMTP   = "smtp is not configured on this server"
	testKind    = "notify.test"
	runFallback = 30 * time.Second
)

// Backoff returns how long to wait after failed attempt n, or giveUp when
// the delivery should be marked failed.
func Backoff(attempt int) (time.Duration, bool) {
	switch {
	case attempt >= MaxAttempts:
		return 0, true
	case attempt == 1:
		return time.Minute, false
	case attempt == 2:
		return 5 * time.Minute, false
	default:
		return 30 * time.Minute, false
	}
}

type Service struct {
	Store  *store.Store
	Sealer *keys.Sealer
	SMTP   config.SMTP
	Mailer Mailer
	Client *http.Client
	Now    func() time.Time
	Log    *slog.Logger
	wake   chan struct{}
}

func New(s *store.Store, sealer *keys.Sealer, smtp config.SMTP, log *slog.Logger) *Service {
	return &Service{
		Store: s, Sealer: sealer, SMTP: smtp, Mailer: NewSMTPMailer(smtp),
		Client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Log:    log, wake: make(chan struct{}, 1),
	}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Emit enqueues one delivery per subscribed channel and wakes the
// dispatcher. Errors are logged only.
func (s *Service) Emit(ctx context.Context, e Event) {
	if e.At.IsZero() {
		e.At = s.now()
	}
	chs, err := s.Store.ChannelsForEvent(ctx, e.TenantID, e.Kind)
	if err != nil {
		s.log().Error("notify: list channels", "kind", e.Kind, "err", err)
		return
	}
	if len(chs) == 0 {
		return
	}
	payload, err := json.Marshal(e)
	if err != nil {
		s.log().Error("notify: marshal event", "kind", e.Kind, "err", err)
		return
	}
	ids := make([]uuid.UUID, 0, len(chs))
	for _, c := range chs {
		ids = append(ids, c.ID)
	}
	if err := s.Store.EnqueueDeliveries(ctx, e.TenantID, ids, e.Kind, payload, s.now()); err != nil {
		s.log().Error("notify: enqueue", "kind", e.Kind, "err", err)
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run drains the outbox whenever woken and every runFallback regardless,
// until ctx is done.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(runFallback)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-t.C:
		}
		for {
			sent, failed, err := s.Dispatch(ctx)
			if err != nil {
				if ctx.Err() == nil {
					s.log().Error("notify: dispatch", "err", err)
				}
				break
			}
			if sent+failed == 0 {
				break
			}
		}
	}
}

// Dispatch claims one batch of due deliveries and sends them. Returns how
// many were sent and how many became terminally failed (retries are neither).
func (s *Service) Dispatch(ctx context.Context) (sent, failed int, err error) {
	now := s.now()
	rows, err := s.Store.ClaimDeliveries(ctx, now, ClaimLease, ClaimBatch)
	if err != nil {
		return 0, 0, err
	}
	for _, d := range rows {
		sendErr := s.deliver(ctx, d)
		switch {
		case sendErr == nil:
			sent++
			err = s.Store.FinishDelivery(ctx, d.ID, "sent", "", time.Time{}, now)
		default:
			var perm permanentError
			if next, giveUp := Backoff(d.Attempts); giveUp || errors.As(sendErr, &perm) {
				failed++
				err = s.Store.FinishDelivery(ctx, d.ID, "failed", sendErr.Error(), time.Time{}, now)
			} else {
				err = s.Store.FinishDelivery(ctx, d.ID, "pending", sendErr.Error(), now.Add(next), now)
			}
		}
		if err != nil {
			s.log().Error("notify: finish delivery", "id", d.ID, "err", err)
		}
	}
	return sent, failed, nil
}

// permanentError marks a failure no retry can fix (channel gone/disabled).
type permanentError struct{ msg string }

func (e permanentError) Error() string { return e.msg }

func (s *Service) deliver(ctx context.Context, d store.Delivery) error {
	ch, err := s.Store.GetChannel(ctx, d.TenantID, d.ChannelID)
	if errors.Is(err, store.ErrNotFound) {
		return permanentError{"channel was deleted"}
	}
	if err != nil {
		return err
	}
	if !ch.Enabled {
		return permanentError{"channel is disabled"}
	}
	var e Event
	if err := json.Unmarshal(d.Payload, &e); err != nil {
		return permanentError{"bad payload: " + err.Error()}
	}
	return s.send(ctx, ch, e, fmt.Sprint(d.ID))
}

func (s *Service) send(ctx context.Context, ch store.NotificationChannel, e Event, deliveryID string) error {
	switch ch.Kind {
	case "webhook":
		var secret []byte
		if len(ch.Secret) > 0 {
			var err error
			if secret, err = s.Sealer.Open(ch.Secret); err != nil {
				return permanentError{"cannot unseal webhook secret"}
			}
		}
		return s.postWebhook(ctx, ch.URL, secret, e, deliveryID)
	case "syslog":
		return sendSyslog(ctx, ch.URL, e)
	case "email":
		if !s.SMTP.Configured() {
			return permanentError{errNoSMTP}
		}
		return s.Mailer.Send(ctx, ch.Recipients, "[FreeLocker] "+e.Title, formatEmailBody(e))
	default:
		return permanentError{"unknown channel kind " + ch.Kind}
	}
}

// Test sends a synthetic event through the channel synchronously and
// returns the delivery error, if any. Nothing is recorded.
func (s *Service) Test(ctx context.Context, ch store.NotificationChannel) error {
	e := Event{Kind: testKind, TenantID: uuid.Nil, Title: "Test notification from FreeLocker",
		Body: "If you can read this, the channel \"" + ch.Name + "\" works.", Detail: map[string]any{"channel": ch.Name}, At: s.now()}
	return s.send(ctx, ch, e, "test")
}
