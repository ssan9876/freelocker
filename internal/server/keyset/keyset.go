// Package keyset resolves and caches per-tenant CA and signing keys, so the
// server can operate many tenants each with its own certificate authority.
// A single-tenant deployment simply resolves the one tenant.
package keyset

import (
	"context"
	"sync"

	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

// Func resolves a tenant's keys. This is the seam threaded through the
// enrollment, agent, command, and policy paths; when nil a caller falls
// back to its single configured *bootstrap.Keys.
type Func func(ctx context.Context, tenantID uuid.UUID) (*bootstrap.Keys, error)

type Provider struct {
	store  *store.Store
	master []byte

	mu    sync.Mutex
	cache map[uuid.UUID]*bootstrap.Keys
}

func New(s *store.Store, master []byte) *Provider {
	return &Provider{store: s, master: master, cache: map[uuid.UUID]*bootstrap.Keys{}}
}

// For returns the tenant's keys, loading and caching them on first use.
func (p *Provider) For(ctx context.Context, tenantID uuid.UUID) (*bootstrap.Keys, error) {
	p.mu.Lock()
	if k, ok := p.cache[tenantID]; ok {
		p.mu.Unlock()
		return k, nil
	}
	p.mu.Unlock()

	k, err := bootstrap.LoadForTenant(ctx, p.store, p.master, tenantID)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.cache[tenantID] = k
	p.mu.Unlock()
	return k, nil
}

// Static returns a resolver that always yields the given keys, for
// single-tenant use and tests.
func Static(k *bootstrap.Keys) Func {
	return func(context.Context, uuid.UUID) (*bootstrap.Keys, error) { return k, nil }
}
