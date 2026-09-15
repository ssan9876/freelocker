package httpapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"mime/multipart"
	"net/http"
	"testing"
)

func TestReleaseUploadAndDownload(t *testing.T) {
	e := newEnv(t)
	c := e.initialized(t)

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	mw.WriteField("version", "1.0.0")
	fw, _ := mw.CreateFormFile("file", "agent.exe")
	payload := []byte("fake-agent-binary")
	fw.Write(payload)
	mw.Close()

	req, _ := http.NewRequest("POST", c.base+"/api/releases", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", c.csrf)
	resp, err := c.http.Do(req)
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("upload = %v %v", resp.StatusCode, err)
	}
	resp.Body.Close()

	want := sha256.Sum256(payload)
	tenant, _ := e.store.FirstTenant(context.Background())
	dl, err := c.http.Get(c.base + "/agent/releases/" + tenant.String() + "/1.0.0")
	if err != nil || dl.StatusCode != 200 {
		t.Fatalf("download = %v %v", dl.StatusCode, err)
	}
	got, _ := io.ReadAll(dl.Body)
	dl.Body.Close()
	if gotSum := sha256.Sum256(got); gotSum != want {
		t.Errorf("downloaded bytes hash mismatch")
	}

	// A path-traversal version must 404, not escape the release dir.
	bad, _ := c.http.Get(c.base + "/agent/releases/" + tenant.String() + "/..%2f..%2fsecret")
	if bad.StatusCode == 200 {
		t.Error("path traversal should not succeed")
	}
	bad.Body.Close()
}

// Release binaries are stored per tenant: two tenants may both ship a version
// called "1.0.0", and the second upload must not overwrite the first — the
// first tenant's agents verify against the sha256 recorded at its own upload.
func TestReleaseUploadIsPerTenant(t *testing.T) {
	e := newEnv(t)
	prov := e.initialized(t)
	const betaOwner, betaPass = "owner@beta.example.com", "beta-password-1234"
	var cr struct {
		TenantID string `json:"tenant_id"`
	}
	prov.do("POST", "/api/provider/tenants", map[string]string{"org_name": "Beta", "owner_email": betaOwner, "owner_password": betaPass}, &cr)
	beta := e.client(t)
	beta.loginFull(betaOwner, betaPass, "")

	provTenant, _ := e.store.FirstTenant(context.Background())
	provBody := []byte("provider-build-of-1.0.0")
	betaBody := []byte("beta-build-of-1.0.0")
	prov.uploadReleaseBody(t, "1.0.0", provBody)
	beta.uploadReleaseBody(t, "1.0.0", betaBody)

	for _, tc := range []struct {
		name   string
		tenant string
		want   []byte
	}{
		{"provider", provTenant.String(), provBody},
		{"beta", cr.TenantID, betaBody},
	} {
		// The download endpoint is unauthenticated; the tenant is in the path.
		dl, err := prov.http.Get(prov.base + "/agent/releases/" + tc.tenant + "/1.0.0")
		if err != nil {
			t.Fatalf("%s download: %v", tc.name, err)
		}
		got, _ := io.ReadAll(dl.Body)
		dl.Body.Close()
		if dl.StatusCode != 200 || !bytes.Equal(got, tc.want) {
			t.Errorf("%s download = %d %q, want %q", tc.name, dl.StatusCode, got, tc.want)
		}
	}
}
