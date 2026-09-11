package httpapi_test

import (
	"bytes"
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
	dl, err := c.http.Get(c.base + "/agent/releases/1.0.0")
	if err != nil || dl.StatusCode != 200 {
		t.Fatalf("download = %v %v", dl.StatusCode, err)
	}
	got, _ := io.ReadAll(dl.Body)
	dl.Body.Close()
	if gotSum := sha256.Sum256(got); gotSum != want {
		t.Errorf("downloaded bytes hash mismatch")
	}

	// A path-traversal version must 404, not escape the release dir.
	bad, _ := c.http.Get(c.base + "/agent/releases/..%2f..%2fsecret")
	if bad.StatusCode == 200 {
		t.Error("path traversal should not succeed")
	}
	bad.Body.Close()
}
