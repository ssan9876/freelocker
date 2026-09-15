// Package alerting evaluates resource-metric samples against threshold
// rules and raises or resolves alerts. Breach onset is persisted in the
// store so a sustained-duration rule is evaluated consistently across
// server instances.
package alerting

import (
	"context"
	"fmt"
	"time"

	"freelocker/internal/server/notify"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type Service struct {
	Store  *store.Store
	Notify notify.Emitter
}

func New(s *store.Store) *Service { return &Service{Store: s} }

// emit builds and sends an event only when a notifier is configured: build
// is a closure so an unconfigured deployment pays no store round trip.
func (s *Service) emit(ctx context.Context, build func() notify.Event) {
	if s.Notify != nil {
		s.Notify.Emit(ctx, build())
	}
}

func metricValue(m string, sample store.MetricSample) (float64, bool) {
	switch m {
	case "cpu":
		return sample.CPUPct, true
	case "mem":
		return sample.MemPct, true
	case "disk":
		return sample.DiskPct, true
	default:
		return 0, false
	}
}

func breaching(op string, value, threshold float64) bool {
	switch op {
	case "gt":
		return value > threshold
	case "lt":
		return value < threshold
	default:
		return false
	}
}

// Evaluate checks the sample against all enabled rules for the tenant,
// raising or resolving alerts as conditions cross and clear.
func (s *Service) Evaluate(ctx context.Context, tenantID, deviceID uuid.UUID, sample store.MetricSample, now time.Time) error {
	rules, err := s.Store.ListEnabledAlertRules(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, r := range rules {
		value, ok := metricValue(r.Metric, sample)
		if !ok {
			continue
		}
		if breaching(r.Op, value, threshold(r)) {
			sustained, err := s.sustained(ctx, tenantID, deviceID, r.ID, r.DurationSeconds, now)
			if err != nil {
				return err
			}
			if sustained {
				msg := fmt.Sprintf("%s %.0f%% %s %.0f%%", r.Metric, value, opWord(r.Op), r.Threshold)
				created, err := s.Store.RaiseAlert(ctx, tenantID, deviceID, r.ID, r.Metric, msg, now)
				if err != nil {
					return err
				}
				if created {
					s.emit(ctx, func() notify.Event {
						return s.alertEvent(ctx, "alert.raised", tenantID, deviceID, r, msg, now)
					})
				}
			}
		} else {
			if err := s.Store.ClearBreach(ctx, tenantID, deviceID, r.ID); err != nil {
				return err
			}
			closed, err := s.Store.ResolveAlert(ctx, tenantID, deviceID, r.ID, now)
			if err != nil {
				return err
			}
			if closed {
				s.emit(ctx, func() notify.Event {
					return s.alertEvent(ctx, "alert.resolved", tenantID, deviceID, r, "", now)
				})
			}
		}
	}
	return nil
}

func threshold(r store.AlertRule) float64 { return r.Threshold }

func opWord(op string) string {
	if op == "lt" {
		return "<"
	}
	return ">"
}

func (s *Service) alertEvent(ctx context.Context, kind string, tenantID, deviceID uuid.UUID, r store.AlertRule, msg string, now time.Time) notify.Event {
	host := deviceID.String()
	if d, err := s.Store.GetDevice(ctx, tenantID, deviceID); err == nil && d.Hostname != "" {
		host = d.Hostname
	}
	title := fmt.Sprintf("Alert: %s on %s", r.Name, host)
	body := fmt.Sprintf("%s is %s on %s.", r.Name, map[string]string{"alert.raised": "breaching", "alert.resolved": "resolved"}[kind], host)
	if msg != "" {
		body += "\n" + msg
	}
	if kind == "alert.resolved" {
		title = fmt.Sprintf("Resolved: %s on %s", r.Name, host)
	}
	return notify.Event{Kind: kind, TenantID: tenantID, Title: title, Body: body, At: now,
		Detail: map[string]any{"device_id": deviceID.String(), "hostname": host, "rule_id": r.ID.String(), "rule_name": r.Name, "metric": r.Metric, "message": msg}}
}

// sustained reports whether a breach has held for at least duration. For
// duration 0 it is immediate. Breach onset is recorded in the store.
func (s *Service) sustained(ctx context.Context, tenantID, deviceID, ruleID uuid.UUID, durationSeconds int, now time.Time) (bool, error) {
	if durationSeconds <= 0 {
		return true, nil
	}
	since, err := s.Store.MarkBreach(ctx, tenantID, deviceID, ruleID, now)
	if err != nil {
		return false, err
	}
	return now.Sub(since) >= time.Duration(durationSeconds)*time.Second, nil
}
