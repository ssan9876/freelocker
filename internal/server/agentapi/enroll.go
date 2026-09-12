package agentapi

import (
	"context"
	"crypto/ed25519"
	"errors"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/store"
	"freelocker/internal/server/tokens"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type enrollService struct {
	flv1.UnimplementedEnrollmentServer
	d Deps
}

var errBadCSR = errors.New("bad CSR")

func (s *enrollService) Enroll(ctx context.Context, req *flv1.EnrollRequest) (*flv1.EnrollResponse, error) {
	if req.GetTokenSecret() == "" || len(req.GetCsrDer()) == 0 || req.GetHardware().GetHostname() == "" {
		return nil, status.Error(codes.InvalidArgument, "token_secret, csr_der and hardware.hostname are required")
	}
	now := s.d.Now()
	deviceID := uuid.New()
	var certDER []byte
	var tenantKeys *keysForResp

	tenantID, err := s.d.Store.EnrollDevice(ctx, tokens.Hash(req.GetTokenSecret()), now, func(tid uuid.UUID) (store.NewDevice, error) {
		k, err := s.d.keys(ctx, tid)
		if err != nil {
			return store.NewDevice{}, err
		}
		der, serial, notAfter, err := k.CA.SignDevice(req.GetCsrDer(), deviceID, now)
		if err != nil {
			return store.NewDevice{}, errors.Join(errBadCSR, err)
		}
		certDER = der
		tenantKeys = &keysForResp{
			caRaw:      k.CA.Cert.Raw,
			commandPub: k.CommandKey.Public().(ed25519.PublicKey),
			updatePub:  k.UpdateKey.Public().(ed25519.PublicKey),
			uninstall:  k.UninstallCodeHash(deviceID),
		}
		hw := req.GetHardware()
		return store.NewDevice{
			ID: deviceID, Hostname: hw.GetHostname(), MachineGUID: hw.GetMachineGuid(), OSBuild: hw.GetOsBuild(),
			CertSerial: serial, CertExpiresAt: notAfter,
		}, nil
	})
	switch {
	case errors.Is(err, store.ErrTokenInvalid):
		s.d.Log.Warn("enrollment rejected", "reason", "token", "hostname", req.GetHardware().GetHostname())
		return nil, status.Error(codes.PermissionDenied, store.ErrTokenInvalid.Error())
	case errors.Is(err, errBadCSR):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case err != nil:
		s.d.Log.Error("enrollment failed", "err", err)
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	if err := s.d.Store.AppendAudit(ctx, tenantID, store.AuditEntry{
		Actor: "device:" + deviceID.String(), Action: "device.enroll", TargetType: "device", TargetID: deviceID.String(),
		Detail: map[string]any{"hostname": req.GetHardware().GetHostname()}, Result: "success",
	}); err != nil {
		s.d.Log.Error("audit write failed", "err", err)
	}

	return &flv1.EnrollResponse{
		DeviceId:                deviceID.String(),
		CertDer:                 certDER,
		CaCertDer:               tenantKeys.caRaw,
		CommandSigningPublicKey: tenantKeys.commandPub,
		UpdateSigningPublicKey:  tenantKeys.updatePub,
		UninstallCodeSha256:     tenantKeys.uninstall,
	}, nil
}

// keysForResp captures the enrolling tenant's public key material for the
// enrollment response, taken while its keys are resolved during the tx.
type keysForResp struct {
	caRaw                 []byte
	commandPub, updatePub ed25519.PublicKey
	uninstall             []byte
}
