package sim

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	flv1 "freelocker/gen/freelocker/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Session struct {
	conn     *grpc.ClientConn
	stream   flv1.Agent_ConnectClient
	commands chan *flv1.SignedCommand
	done     chan error
}

func dial(addr string, id *Identity) (*grpc.ClientConn, error) {
	cfg, err := id.TLSConfig()
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
}

func Connect(ctx context.Context, addr string, id *Identity) (*Session, error) {
	conn, err := dial(addr, id)
	if err != nil {
		return nil, err
	}
	stream, err := flv1.NewAgentClient(conn).Connect(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}
	s := &Session{conn: conn, stream: stream, commands: make(chan *flv1.SignedCommand, 64), done: make(chan error, 1)}
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				s.done <- err
				close(s.commands)
				return
			}
			if c := m.GetCommand(); c != nil {
				s.commands <- c
			}
		}
	}()
	return s, nil
}

func (s *Session) Heartbeat(inv *flv1.Inventory) error {
	return s.stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_Heartbeat{Heartbeat: &flv1.Heartbeat{
		Inventory: inv, SentAtUnix: time.Now().Unix(),
	}}})
}

func (s *Session) SendResult(r *flv1.CommandResult) error {
	return s.stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_CommandResult{CommandResult: r}})
}

func (s *Session) Goodbye(reason string) error {
	if err := s.stream.Send(&flv1.AgentMessage{Body: &flv1.AgentMessage_Goodbye{Goodbye: &flv1.Goodbye{Reason: reason}}}); err != nil {
		return err
	}
	return s.stream.CloseSend()
}

func (s *Session) Commands() <-chan *flv1.SignedCommand { return s.commands }
func (s *Session) Done() <-chan error                   { return s.done }
func (s *Session) Close() error                         { return s.conn.Close() }

// Renew obtains a new certificate with a fresh key and returns the
// updated identity; the old certificate stops working immediately.
func Renew(ctx context.Context, addr string, id *Identity) (*Identity, error) {
	conn, err := dial(addr, id)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.DeviceID}}, key)
	if err != nil {
		return nil, err
	}
	resp, err := flv1.NewAgentClient(conn).RenewCertificate(ctx, &flv1.RenewRequest{CsrDer: csr})
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	next := *id
	next.CertDER, next.KeyDER = resp.GetCertDer(), keyDER
	return &next, nil
}
