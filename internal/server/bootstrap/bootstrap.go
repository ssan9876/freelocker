// Package bootstrap performs first-run initialization (tenant, CA,
// signing keys) and loads those keys at server start.
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"freelocker/internal/server/ca"
	"freelocker/internal/server/keys"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

var ErrAlreadyInitialized = errors.New("server already initialized")

const (
	sealPurpose      = "server-keys"
	uninstallPurpose = "uninstall-code"
	keyCA            = "ca"
	keyCommand       = "command-signing"
	keyUpdate        = "update-signing"
)

type Keys struct {
	TenantID     uuid.UUID
	CA           *ca.CA
	CommandKey   ed25519.PrivateKey
	UpdateKey    ed25519.PrivateKey
	uninstallKey []byte
}

func Init(ctx context.Context, s *store.Store, master []byte, tenantName string, now time.Time) (uuid.UUID, error) {
	if _, err := s.FirstTenant(ctx); err == nil {
		return uuid.Nil, ErrAlreadyInitialized
	} else if !errors.Is(err, store.ErrNotFound) {
		return uuid.Nil, err
	}
	sealer, err := keys.NewSealer(master, sealPurpose)
	if err != nil {
		return uuid.Nil, err
	}
	tenant, err := s.CreateTenant(ctx, tenantName)
	if err != nil {
		return uuid.Nil, err
	}

	authority, err := ca.New(tenantName+" FreeLocker CA", now)
	if err != nil {
		return uuid.Nil, err
	}
	caKey, err := authority.MarshalKey()
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.PutServerKey(ctx, tenant, keyCA, authority.Cert.Raw, sealer.Seal(caKey)); err != nil {
		return uuid.Nil, err
	}
	for _, name := range []string{keyCommand, keyUpdate} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return uuid.Nil, err
		}
		if err := s.PutServerKey(ctx, tenant, name, pub, sealer.Seal(priv)); err != nil {
			return uuid.Nil, err
		}
	}
	return tenant, nil
}

func Load(ctx context.Context, s *store.Store, master []byte) (*Keys, error) {
	tenant, err := s.FirstTenant(ctx)
	if err != nil {
		return nil, fmt.Errorf("load tenant (run `freelocker-server init` first?): %w", err)
	}
	sealer, err := keys.NewSealer(master, sealPurpose)
	if err != nil {
		return nil, err
	}
	open := func(name string) (pub, priv []byte, err error) {
		pub, sealed, err := s.GetServerKey(ctx, tenant, name)
		if err != nil {
			return nil, nil, fmt.Errorf("load key %s: %w", name, err)
		}
		priv, err = sealer.Open(sealed)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt key %s (wrong master secret?): %w", name, err)
		}
		return pub, priv, nil
	}

	certDER, caKey, err := open(keyCA)
	if err != nil {
		return nil, err
	}
	authority, err := ca.Load(certDER, caKey)
	if err != nil {
		return nil, err
	}
	_, cmdKey, err := open(keyCommand)
	if err != nil {
		return nil, err
	}
	_, updKey, err := open(keyUpdate)
	if err != nil {
		return nil, err
	}
	uk, err := keys.Derive(master, uninstallPurpose)
	if err != nil {
		return nil, err
	}
	return &Keys{
		TenantID:     tenant,
		CA:           authority,
		CommandKey:   ed25519.PrivateKey(cmdKey),
		UpdateKey:    ed25519.PrivateKey(updKey),
		uninstallKey: uk,
	}, nil
}

// UninstallCode is derived, not stored, so the console can always show it.
func (k *Keys) UninstallCode(deviceID uuid.UUID) string {
	m := hmac.New(sha256.New, k.uninstallKey)
	m.Write(deviceID[:])
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(m.Sum(nil)[:10])
}

func (k *Keys) UninstallCodeHash(deviceID uuid.UUID) []byte {
	sum := sha256.Sum256([]byte(k.UninstallCode(deviceID)))
	return sum[:]
}
