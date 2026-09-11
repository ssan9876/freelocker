//go:build !windows

package inventory

import (
	"time"

	flv1 "freelocker/gen/freelocker/v1"
)

type portable struct{ Base }

func New() Collector { return portable{Base{StartedAt: time.Now()}} }

func (p portable) Collect() *flv1.Inventory { return p.base() }
