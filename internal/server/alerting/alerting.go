// Package alerting evaluates resource-metric samples against threshold
// rules and raises or resolves alerts. Breach onset is persisted in the
// store so a sustained-duration rule is evaluated consistently across
// server instances.
package alerting

import (
	"context"
	"fmt"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type Service struct {
	Store *store.Store
}

func New(s *store.Store) *Service { return &Service{Store: s} }

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
				if _, err := s.Store.RaiseAlert(ctx, tenantID, deviceID, r.ID, r.Metric, msg, now); err != nil {
					return err
				}
			}
		} else {
			if err := s.Store.ClearBreach(ctx, tenantID, deviceID, r.ID); err != nil {
				return err
			}
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
