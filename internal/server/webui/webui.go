// Package webui embeds the built React console and serves it as a
// single-page app. When the build output is absent (a checkout that has
// not run `npm run build`), Enabled reports false and the server serves
// only the API.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

// dist is the embedded build directory, or nil when only the .gitkeep
// placeholder is present.
func dist() (fs.FS, bool) {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return sub, true
}

// Enabled reports whether a console build is embedded.
func Enabled() bool {
	_, ok := dist()
	return ok
}

// Handler serves static assets and falls back to index.html for client-side
// routes. Callers should only mount it for non-API paths.
func Handler() http.Handler {
	sub, ok := dist()
	if !ok {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "console UI not built; run `npm --prefix web run build`", http.StatusNotFound)
		})
	}
	files := http.FileServer(http.FS(sub))
	index, _ := fs.ReadFile(sub, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" {
			serveIndex(w, index)
			return
		}
		if _, err := fs.Stat(sub, clean); err != nil {
			// Unknown path: hand it to the SPA router.
			serveIndex(w, index)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, index []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(index)
}
