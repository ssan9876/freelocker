package httpapi

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"freelocker/internal/server/store"

	"github.com/go-chi/chi/v5"
)

func (a *API) uploadRelease(w http.ResponseWriter, r *http.Request) {
	if a.ReleaseDir == "" {
		writeErr(w, http.StatusServiceUnavailable, "release hosting not configured")
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "expected multipart form with version and file")
		return
	}
	version := strings.TrimSpace(r.FormValue("version"))
	if version == "" || strings.ContainsAny(version, `/\`) || strings.Contains(version, "..") {
		writeErr(w, http.StatusBadRequest, "version is required and must be a plain version string")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	if err := os.MkdirAll(a.ReleaseDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create release dir")
		return
	}
	dst := filepath.Join(a.ReleaseDir, version+".exe")
	out, err := os.Create(dst)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not write release")
		return
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), file); err != nil {
		out.Close()
		writeErr(w, http.StatusInternalServerError, "could not store release")
		return
	}
	out.Close()
	sum := h.Sum(nil)
	p := principalFrom(r)
	k, err := a.keysFor(r.Context(), p.TenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not resolve signing key")
		return
	}
	sig := ed25519.Sign(k.UpdateKey, sum)
	if err := a.Store.PutRelease(r.Context(), p.TenantID, store.Release{Version: version, SHA256: sum, Signature: sig, UploadedAt: time.Now()}); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "release.upload", "release", version, map[string]any{"sha256": hex.EncodeToString(sum)}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"version": version, "sha256": hex.EncodeToString(sum)})
}

func (a *API) listReleases(w http.ResponseWriter, r *http.Request) {
	rels, err := a.Store.ListReleases(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rels))
	for _, rel := range rels {
		out = append(out, map[string]any{"version": rel.Version, "sha256": hex.EncodeToString(rel.SHA256), "uploaded_at": rel.UploadedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// downloadRelease is unauthenticated; the agent verifies hash + signature.
func (a *API) downloadRelease(w http.ResponseWriter, r *http.Request) {
	version := chi.URLParam(r, "version")
	if a.ReleaseDir == "" || strings.ContainsAny(version, `/\`) || strings.Contains(version, "..") {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	f, err := os.Open(filepath.Join(a.ReleaseDir, version+".exe"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}
