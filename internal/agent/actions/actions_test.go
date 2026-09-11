package actions

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	flv1 "freelocker/gen/freelocker/v1"
	"freelocker/internal/agent/agentpaths"
	"freelocker/internal/server/commands"
)

func TestUpdateAgentRejectsBadSignature(t *testing.T) {
	payload := []byte("agent-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	defer srv.Close()
	sum := sha256.Sum256(payload)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)

	a := &Actions{
		Paths:     agentpaths.Paths{InstallDir: t.TempDir()},
		UpdatePub: func() ed25519.PublicKey { return pub },
		StageOnly: true,
	}
	cmd := &flv1.Command{Type: flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT,
		Payload: commands.MarshalUpdate(commands.UpdatePayload{
			URL: srv.URL, Version: "9.9.9", SHA256: sum[:], Signature: ed25519.Sign(wrongPriv, sum[:]),
		})}
	if err := a.UpdateAgent(context.Background(), cmd); err == nil {
		t.Fatal("update with wrong signature must fail")
	}
}

func TestUpdateAgentAcceptsGoodSignatureStageOnly(t *testing.T) {
	payload := []byte("agent-bytes-2")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	defer srv.Close()
	sum := sha256.Sum256(payload)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	a := &Actions{
		Paths:     agentpaths.Paths{InstallDir: t.TempDir()},
		UpdatePub: func() ed25519.PublicKey { return pub },
		StageOnly: true,
	}
	cmd := &flv1.Command{Type: flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT,
		Payload: commands.MarshalUpdate(commands.UpdatePayload{
			URL: srv.URL, Version: "9.9.9", SHA256: sum[:], Signature: ed25519.Sign(priv, sum[:]),
		})}
	if err := a.UpdateAgent(context.Background(), cmd); err != nil {
		t.Fatalf("valid update rejected: %v", err)
	}
}
