// Package agentapi implements the gRPC services that agents talk to.
package agentapi

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"time"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/server/alerting"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/policysvc"
	"freelocker/internal/server/store"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

type Deps struct {
	Store    *store.Store
	Keys     *bootstrap.Keys
	Hub      *hub.Hub
	Commands CommandSink        // optional
	Policy   *policysvc.Service // optional; enables GetPolicy
	Alerting *alerting.Service  // optional; evaluates metrics on report
	Now      func() time.Time
	Log      *slog.Logger
}

// TLSConfig issues a fresh agent-facing server certificate from the
// internal CA. Client certs are optional at the TLS layer because
// Enroll is called before the agent has one; the Agent service
// enforces them in an interceptor.
func TLSConfig(k *bootstrap.Keys, hostnames []string, now time.Time) (*tls.Config, error) {
	cert, err := k.CA.IssueServerCert(hostnames, now)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(k.CA.Cert)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func NewGRPCServer(d Deps, tlsCfg *tls.Config) *grpc.Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Hub == nil {
		d.Hub = hub.New()
	}
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.ChainUnaryInterceptor(d.unaryAuth),
		grpc.ChainStreamInterceptor(d.streamAuth),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 60 * time.Second, Timeout: 20 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 20 * time.Second, PermitWithoutStream: true}),
	)
	flv1.RegisterEnrollmentServer(srv, &enrollService{d: d})
	flv1.RegisterAgentServer(srv, &agentService{d: d})
	return srv
}
