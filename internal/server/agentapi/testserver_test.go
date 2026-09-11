package agentapi_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"freelocker/internal/server/agentapi"
	"freelocker/internal/server/bootstrap"
	"freelocker/internal/server/alerting"
	"freelocker/internal/server/commands"
	"freelocker/internal/server/hub"
	"freelocker/internal/server/policysvc"
	"freelocker/internal/server/store"
	"freelocker/internal/server/store/storetest"
	"freelocker/internal/server/tokens"
)

type testServer struct {
	Addr  string
	Deps  agentapi.Deps
	Token string // valid unlimited install token
}

func startServer(t *testing.T) *testServer {
	t.Helper()
	ctx := context.Background()
	s := storetest.New(t)
	master := bytes.Repeat([]byte{9}, 32)
	if _, err := bootstrap.Init(ctx, s, master, "Acme", time.Now()); err != nil {
		t.Fatal(err)
	}
	k, err := bootstrap.Load(ctx, s, master)
	if err != nil {
		t.Fatal(err)
	}
	full, hash, _ := tokens.Generate(k.CA.Pin())
	if _, err := s.CreateInstallToken(ctx, k.TenantID, store.InstallToken{Name: "test"}, hash); err != nil {
		t.Fatal(err)
	}

	d := newDeps(s, k)
	tlsCfg, err := agentapi.TLSConfig(k, []string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := agentapi.NewGRPCServer(d, tlsCfg)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return &testServer{Addr: lis.Addr().String(), Deps: d, Token: full}
}

func newDeps(s *store.Store, k *bootstrap.Keys) agentapi.Deps {
	h := hub.New()
	return agentapi.Deps{
		Store: s, Keys: k, Hub: h,
		Commands: &commands.Service{Store: s, Keys: k, Hub: h},
		Policy:   &policysvc.Service{Store: s, Keys: k},
		Alerting: alerting.New(s),
	}
}
