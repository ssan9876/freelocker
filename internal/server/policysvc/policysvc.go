// Package policysvc compiles application-control policies to signed WDAC
// versions and resolves the effective policy for a device.
package policysvc

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"freelocker/internal/appcontrol/rules"
	"freelocker/internal/appcontrol/wdac"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type Service struct {
	Store *store.Store
	Keys  *bootstrap.Keys
}

// Recompile builds the current rule set into a signed WDAC version and
// stores it, returning the new version id (the XML content hash).
func (s *Service) Recompile(ctx context.Context, tenantID, policyID uuid.UUID) (string, error) {
	p, err := s.Store.GetPolicy(ctx, tenantID, policyID)
	if err != nil {
		return "", err
	}
	stored, err := s.Store.ListRules(ctx, tenantID, policyID)
	if err != nil {
		return "", err
	}
	rs := make([]rules.Rule, 0, len(stored))
	for _, r := range stored {
		rs = append(rs, rules.Rule{
			Kind: rules.Kind(r.Kind), Value: r.Value, PublisherName: r.PublisherName, Description: r.Description,
		})
	}
	xml, err := wdac.Compile(wdac.Policy{Mode: p.Mode, Rules: rs})
	if err != nil {
		return "", fmt.Errorf("compile policy: %w", err)
	}
	version := wdac.ContentHash(xml)
	sig := ed25519.Sign(s.Keys.UpdateKey, []byte(version))
	err = s.Store.PutPolicyVersion(ctx, tenantID, store.PolicyVersion{
		PolicyID: policyID, Version: version, Mode: p.Mode, XML: xml, Signature: sig,
	})
	if err != nil {
		return "", err
	}
	return version, nil
}

// EffectiveXML is the compiled policy a device should apply, or a default
// deny-all audit policy when the device has no assignment.
type Effective struct {
	Version   string
	Mode      string
	XML       []byte
	Signature []byte
}

func (s *Service) Effective(ctx context.Context, tenantID, deviceID uuid.UUID) (Effective, error) {
	v, err := s.Store.EffectivePolicyForDevice(ctx, tenantID, deviceID)
	if err == store.ErrNotFound {
		return s.denyAll()
	}
	if err != nil {
		return Effective{}, err
	}
	return Effective{Version: v.Version, Mode: v.Mode, XML: v.XML, Signature: v.Signature}, nil
}

// denyAll is the safe default for an unassigned device: an audit-mode
// policy with no allow rules (logs would-be blocks, blocks nothing).
func (s *Service) denyAll() (Effective, error) {
	xml, err := wdac.Compile(wdac.Policy{Mode: "audit"})
	if err != nil {
		return Effective{}, err
	}
	version := wdac.ContentHash(xml)
	return Effective{
		Version: version, Mode: "audit", XML: xml,
		Signature: ed25519.Sign(s.Keys.UpdateKey, []byte(version)),
	}, nil
}

// Verify checks a policy signature against the server's update public key.
func Verify(pub ed25519.PublicKey, version string, signature []byte) bool {
	return ed25519.Verify(pub, []byte(version), signature)
}
