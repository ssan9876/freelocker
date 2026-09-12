package agentapi

import (
	"context"
	"errors"
	"strings"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const agentServicePrefix = "/freelocker.v1.Agent/"

type deviceKey struct{}

type device struct {
	ID       uuid.UUID
	TenantID uuid.UUID
}

func deviceFrom(ctx context.Context) device { return ctx.Value(deviceKey{}).(device) }

func RevokedError() error { return status.Error(codes.Unauthenticated, "device revoked") }

// authenticate derives the device from the verified client certificate
// and checks it is the device's current, unrevoked certificate.
func (d Deps) authenticate(ctx context.Context) (context.Context, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	leaf := ti.State.VerifiedChains[0][0]
	id, err := uuid.Parse(leaf.Subject.CommonName)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "certificate is not a device certificate")
	}
	tenantID, serial, revoked, err := d.Store.DeviceAuthState(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, status.Error(codes.Unauthenticated, "unknown device")
	case err != nil:
		return nil, status.Error(codes.Internal, "auth lookup failed")
	case revoked:
		return nil, RevokedError()
	case serial != leaf.SerialNumber.Text(16):
		return nil, status.Error(codes.Unauthenticated, "certificate superseded")
	}
	// A suspended tenant's devices keep their identity (they retry and resume
	// on unsuspend) but are refused service meanwhile.
	suspended, err := d.Store.TenantSuspended(ctx, tenantID)
	if err != nil {
		return nil, status.Error(codes.Internal, "auth lookup failed")
	}
	if suspended {
		return nil, status.Error(codes.PermissionDenied, "tenant suspended")
	}
	return context.WithValue(ctx, deviceKey{}, device{ID: id, TenantID: tenantID}), nil
}

func (d Deps) unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	if !strings.HasPrefix(info.FullMethod, agentServicePrefix) {
		return h(ctx, req)
	}
	ctx, err := d.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	return h(ctx, req)
}

func (d Deps) streamAuth(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	if !strings.HasPrefix(info.FullMethod, agentServicePrefix) {
		return h(srv, ss)
	}
	ctx, err := d.authenticate(ss.Context())
	if err != nil {
		return err
	}
	return h(srv, &authedStream{ServerStream: ss, ctx: ctx})
}

type authedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authedStream) Context() context.Context { return s.ctx }
