// Package alerting evaluates resource-metric samples against threshold
// rules and raises or resolves alerts. Breach onset is tracked in memory
// (single-instance v1); a multi-instance deployment would persist it.
package alerting

import (
	"context"
	"fmt"
	"sync"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type Service struct {
	Store *store.Store

	mu     sync.Mutex
	breach map[string]time.Time // deviceID|ruleID -> first-breach time
}

func New(s *store.Store) *Service { return &Service{Store: s, breach: map[string]time.Time{}} }

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
		key := deviceID.String() + "|" + r.ID.String()
		if breaching(r.Op, value, threshold(r)) {
			if s.sustained(key, r.DurationSeconds, now) {
				msg := fmt.Sprintf("%s %.0f%% %s %.0f%%", r.Metric, value, opWord(r.Op), r.Threshold)
				if _, err := s.Store.RaiseAlert(ctx, tenantID, deviceID, r.ID, r.Metric, msg, now); err != nil {
					return err
				}
			}
		} else {
			s.clear(key)
			if err := s.Store.ResolveAlert(ctx, tenantID, deviceID, r.ID, now); err != nil {
				return err
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

// sustained reports whether a breach has held for at least duration. For
// duration 0 it is immediate.
func (s *Service) sustained(key string, durationSeconds int, now time.Time) bool {
	if durationSeconds <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	start, ok := s.breach[key]
	if !ok {
		s.breach[key] = now
		return false
	}
	return now.Sub(start) >= time.Duration(durationSeconds)*time.Second
}

func (s *Service) clear(key string) {
	s.mu.Lock()
	delete(s.breach, key)
	s.mu.Unlock()
}
