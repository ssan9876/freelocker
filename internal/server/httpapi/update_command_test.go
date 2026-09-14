package httpapi_test

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"testing"

	"freelocker/internal/server/commands"
)

// uploadRelease pushes a fake binary through the real upload endpoint so a
// release row + file exist for the tenant.
func (c *client) uploadRelease(t *testing.T, version string) {
	t.Helper()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	mw.WriteField("version", version)
	fw, _ := mw.CreateFormFile("file", "agent.exe")
	fw.Write([]byte("fake-agent-binary-" + version))
	mw.Close()
	req, _ := http.NewRequest("POST", c.base+"/api/releases", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", c.csrf)
	resp, err := c.http.Do(req)
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("upload %s = %v %v", version, resp.StatusCode, err)
	}
	resp.Body.Close()
}

func TestUpdateAgentCommandCarriesReleasePayload(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)
	dev := e.fakeDevice(t)

	// No release yet → 409.
	if code := c.do("POST", "/api/devices/"+dev.String()+"/commands", map[string]string{"type": "update_agent"}, nil); code != 409 {
		t.Fatalf("no release: code = %d, want 409", code)
	}

	c.uploadRelease(t, "1.0.0")
	c.uploadRelease(t, "1.0.1") // latest
	var res idResp
	if code := c.do("POST", "/api/devices/"+dev.String()+"/commands", map[string]string{"type": "update_agent"}, &res); code != 201 {
		t.Fatalf("issue = %d", code)
	}

	k := e.rt().Keys
	cmds, err := e.store.ListDeviceCommands(context.Background(), k.TenantID, dev, 10)
	if err != nil || len(cmds) != 1 {
		t.Fatalf("commands = %v, %v", cmds, err)
	}
	p, err := commands.ParseUpdate(cmds[0].Payload)
	if err != nil {
		t.Fatalf("payload not parseable: %v", err)
	}
	if p.Version != "1.0.1" || p.URL != "http://test.local/agent/releases/1.0.1" || len(p.SHA256) != 32 || len(p.Signature) == 0 {
		t.Errorf("payload = %+v", p)
	}
}
