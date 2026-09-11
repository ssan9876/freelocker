package commands

import "testing"

func TestUpdatePayloadRoundtrip(t *testing.T) {
	p := UpdatePayload{Version: "1.2.3", URL: "https://s/agent/releases/1.2.3", SHA256: []byte("hash"), Signature: []byte("sig")}
	got, err := ParseUpdate(MarshalUpdate(p))
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != p.Version || got.URL != p.URL || string(got.SHA256) != "hash" || string(got.Signature) != "sig" {
		t.Fatalf("roundtrip = %+v", got)
	}
	if _, err := ParseUpdate([]byte("{bad")); err == nil {
		t.Error("bad json must fail")
	}
}
