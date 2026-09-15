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
	"github.com/google/uuid"
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

	p := principalFrom(r)
	dir := filepath.Join(a.ReleaseDir, p.TenantID.String())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create release dir")
		return
	}
	out, err := os.Create(filepath.Join(dir, version+".exe"))
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

// downloadRelease is unauthenticated; the agent verifies hash + signature
// against the values in the signed update command, so serving the file needs
// no session. The tenant is in the path: two tenants may ship the same
// version string with different binaries.
func (a *API) downloadRelease(w http.ResponseWriter, r *http.Request) {
	version, ok := releaseVersion(r)
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	tenant, err := uuid.Parse(chi.URLParam(r, "tenant"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	// Fall back to the flat path for releases uploaded by a server from
	// before release files were stored per tenant.
	if !a.serveRelease(w, filepath.Join(a.ReleaseDir, tenant.String(), version+".exe")) &&
		!a.serveRelease(w, filepath.Join(a.ReleaseDir, version+".exe")) {
		writeErr(w, http.StatusNotFound, "not found")
	}
}

// downloadLegacyRelease serves the pre-tenant-scoping URL, which update
// commands issued before the upgrade still point at.
func (a *API) downloadLegacyRelease(w http.ResponseWriter, r *http.Request) {
	version, ok := releaseVersion(r)
	if !ok || !a.serveRelease(w, filepath.Join(a.ReleaseDir, version+".exe")) {
		writeErr(w, http.StatusNotFound, "not found")
	}
}

// releaseVersion returns the version from the path, rejecting anything that
// could escape the release dir.
func releaseVersion(r *http.Request) (string, bool) {
	v := chi.URLParam(r, "version")
	return v, v != "" && !strings.ContainsAny(v, `/\`) && !strings.Contains(v, "..")
}

func (a *API) serveRelease(w http.ResponseWriter, path string) bool {
	if a.ReleaseDir == "" {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
	return true
}
