package agentapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	"freelocker/internal/server/keyset"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

// TenantTLS builds the agent-facing mTLS config for a multi-tenant server.
// Agents send their tenant's CA pin as SNI; the server presents a server
// certificate signed by that tenant's CA (with the pin in its SANs) and
// trusts the union of all tenant CAs for client-certificate auth. This lets
// each tenant's agents complete the handshake against their own CA.
//
// A single-tenant deployment is just the one-tenant case: its agents send
// the one pin and get the one cert.
type TenantTLS struct {
	provider  *keyset.Provider
	store     *store.Store
	hostnames []string
	now       func() time.Time
	ttl       time.Duration

	mu          sync.Mutex
	refreshedAt time.Time
	pinToTenant map[string]uuid.UUID
	defaultTID  uuid.UUID
	serverCerts map[uuid.UUID]*tls.Certificate
	clientCAs   *x509.CertPool
}

func NewTenantTLS(provider *keyset.Provider, s *store.Store, hostnames []string, now func() time.Time) *TenantTLS {
	if now == nil {
		now = time.Now
	}
	return &TenantTLS{
		provider: provider, store: s, hostnames: hostnames, now: now, ttl: 30 * time.Second,
		pinToTenant: map[string]uuid.UUID{}, serverCerts: map[uuid.UUID]*tls.Certificate{},
	}
}

// Config returns a *tls.Config for the agent gRPC listener. Cert selection
// and the client-CA pool are resolved per connection so tenants added at
// runtime are picked up.
func (t *TenantTLS) Config() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: t.getCertificate,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			pool, err := t.clientCAPool()
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:     tls.VersionTLS13,
				GetCertificate: t.getCertificate,
				ClientAuth:     tls.VerifyClientCertIfGiven,
				ClientCAs:      pool,
			}, nil
		},
	}
}

func (t *TenantTLS) refresh(ctx context.Context) error {
	t.mu.Lock()
	fresh := time.Since(t.refreshedAt) < t.ttl && len(t.pinToTenant) > 0
	t.mu.Unlock()
	if fresh {
		return nil
	}
	tenants, err := t.store.ListTenants(ctx)
	if err != nil {
		return err
	}
	pinMap := map[string]uuid.UUID{}
	pool := x509.NewCertPool()
	var def uuid.UUID
	for i, tid := range tenants {
		k, err := t.provider.For(ctx, tid)
		if err != nil {
			return err
		}
		pinMap[k.CA.Pin()] = tid
		pool.AddCert(k.CA.Cert)
		if i == 0 {
			def = tid
		}
	}
	t.mu.Lock()
	t.pinToTenant, t.clientCAs, t.defaultTID, t.refreshedAt = pinMap, pool, def, t.now()
	t.mu.Unlock()
	return nil
}

func (t *TenantTLS) clientCAPool() (*x509.CertPool, error) {
	if err := t.refresh(context.Background()); err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.clientCAs, nil
}

func (t *TenantTLS) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	ctx := context.Background()
	if err := t.refresh(ctx); err != nil {
		return nil, err
	}
	t.mu.Lock()
	tid, ok := t.pinToTenant[hello.ServerName]
	if !ok {
		tid = t.defaultTID // empty/unknown SNI (e.g. host-based) → default tenant
	}
	if cert, cached := t.serverCerts[tid]; cached {
		t.mu.Unlock()
		return cert, nil
	}
	t.mu.Unlock()

	k, err := t.provider.For(ctx, tid)
	if err != nil {
		return nil, err
	}
	// Include the tenant's pin as a SAN so an agent that verifies the
	// hostname (Connect uses ServerName = pin) accepts the cert.
	sans := append(append([]string{}, t.hostnames...), k.CA.Pin())
	cert, err := k.CA.IssueServerCert(sans, t.now())
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.serverCerts[tid] = &cert
	t.mu.Unlock()
	return &cert, nil
}

// ServerName returns the SNI value an agent should send for a given CA pin.
// It is simply the pin; kept as a function so the convention has one home.
func ServerName(caPin string) string { return caPin }
