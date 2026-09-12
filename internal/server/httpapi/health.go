package httpapi

import "net/http"

// health reports liveness: the process is up and serving. Always 200.
func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ready reports readiness: the database is reachable and whether the
// server has been initialized. 503 until the DB is reachable.
func (a *API) ready(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "database": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"database":    true,
		"initialized": a.Runtime() != nil,
	})
}
