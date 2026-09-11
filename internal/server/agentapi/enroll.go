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

	tenantID, err := s.d.Store.EnrollDevice(ctx, tokens.Hash(req.GetTokenSecret()), now, func(uuid.UUID) (store.NewDevice, error) {
		der, serial, notAfter, err := s.d.Keys.CA.SignDevice(req.GetCsrDer(), deviceID, now)
		if err != nil {
			return store.NewDevice{}, errors.Join(errBadCSR, err)
		}
		certDER = der
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
		CaCertDer:               s.d.Keys.CA.Cert.Raw,
		CommandSigningPublicKey: s.d.Keys.CommandKey.Public().(ed25519.PublicKey),
		UpdateSigningPublicKey:  s.d.Keys.UpdateKey.Public().(ed25519.PublicKey),
		UninstallCodeSha256:     s.d.Keys.UninstallCodeHash(deviceID),
	}, nil
}
