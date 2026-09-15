package httpapi

import (
	"errors"
	"net/http"
	"time"

	"freelocker/internal/server/store"

	"github.com/google/uuid"
)

type rolloutSummaryJSON struct {
	Targeted       int `json:"targeted"`
	AlreadyCurrent int `json:"already_current"`
	Issued         int `json:"issued"`
	Updated        int `json:"updated"`
	Failed         int `json:"failed"`
	Remaining      int `json:"remaining"`
}

type rolloutJSON struct {
	ID          string             `json:"id"`
	Version     string             `json:"version"`
	GroupIDs    []string           `json:"group_ids"`
	BatchSize   int                `json:"batch_size"`
	MaxFailures int                `json:"max_failures"`
	State       string             `json:"state"`
	CreatedBy   string             `json:"created_by"`
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	FinishedAt  *time.Time         `json:"finished_at"`
	Summary     rolloutSummaryJSON `json:"summary"`
}

type rolloutDeviceJSON struct {
	DeviceID   string     `json:"device_id"`
	Hostname   string     `json:"hostname"`
	CommandID  string     `json:"command_id"`
	State      string     `json:"state"`
	Detail     string     `json:"detail"`
	IssuedAt   time.Time  `json:"issued_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
}

type rolloutDetailJSON struct {
	rolloutJSON
	Devices []rolloutDeviceJSON `json:"devices"`
}

func toRolloutJSON(r store.Rollout, s store.RolloutSummary) rolloutJSON {
	gids := make([]string, 0, len(r.GroupIDs))
	for _, g := range r.GroupIDs {
		gids = append(gids, g.String())
	}
	return rolloutJSON{
		ID: r.ID.String(), Version: r.Version, GroupIDs: gids, BatchSize: r.BatchSize, MaxFailures: r.MaxFailures,
		State: r.State, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, FinishedAt: r.FinishedAt,
		Summary: rolloutSummaryJSON{s.Targeted, s.AlreadyCurrent, s.Issued, s.Updated, s.Failed, s.Remaining},
	}
}

const (
	defaultRolloutBatch       = 10
	defaultRolloutMaxFailures = 3
)

type rolloutCreateReq struct {
	Version     string   `json:"version"`
	GroupIDs    []string `json:"group_ids"`
	BatchSize   *int     `json:"batch_size"`
	MaxFailures *int     `json:"max_failures"`
}

// newRollout validates a create request into a store.Rollout.
func newRollout(req rolloutCreateReq, actor string) (store.Rollout, string) {
	r := store.Rollout{ID: uuid.New(), Version: req.Version, State: "active", CreatedBy: actor, BatchSize: defaultRolloutBatch, MaxFailures: defaultRolloutMaxFailures, GroupIDs: []uuid.UUID{}}
	if r.Version == "" {
		return r, "version is required"
	}
	if req.BatchSize != nil {
		r.BatchSize = *req.BatchSize
	}
	if req.MaxFailures != nil {
		r.MaxFailures = *req.MaxFailures
	}
	if r.BatchSize < 1 {
		return r, "batch_size must be at least 1"
	}
	if r.MaxFailures < 0 {
		return r, "max_failures must be 0 or more"
	}
	for _, g := range req.GroupIDs {
		id, err := uuid.Parse(g)
		if err != nil {
			return r, "bad group id"
		}
		r.GroupIDs = append(r.GroupIDs, id)
	}
	return r, ""
}

func (a *API) createRollout(w http.ResponseWriter, r *http.Request) {
	var req rolloutCreateReq
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r)
	ro, msg := newRollout(req, "admin:"+p.Admin.Email)
	if msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if err := a.Store.CreateRollout(r.Context(), p.TenantID, ro); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "rollout.create", "rollout", ro.ID.String(), map[string]any{"version": ro.Version, "group_ids": req.GroupIDs, "batch_size": ro.BatchSize, "max_failures": ro.MaxFailures}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": ro.ID.String()})
}

func (a *API) listRollouts(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	list, err := a.Store.ListRollouts(r.Context(), p.TenantID, queryInt(r, "limit", 50, 200))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	ids := make([]uuid.UUID, len(list))
	for i, ro := range list {
		ids[i] = ro.ID
	}
	sums, err := a.Store.RolloutSummaries(r.Context(), p.TenantID, ids)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]rolloutJSON, 0, len(list))
	for _, ro := range list {
		out = append(out, toRolloutJSON(ro, sums[ro.ID]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) getRollout(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	ro, err := a.Store.GetRollout(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	sum, err := a.Store.RolloutSummary(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	devs, err := a.Store.ListRolloutDevices(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := rolloutDetailJSON{rolloutJSON: toRolloutJSON(ro, sum), Devices: make([]rolloutDeviceJSON, 0, len(devs))}
	for _, d := range devs {
		out.Devices = append(out.Devices, rolloutDeviceJSON{
			DeviceID: d.DeviceID.String(), Hostname: d.Hostname, CommandID: d.CommandID.String(),
			State: d.State, Detail: d.Detail, IssuedAt: d.IssuedAt, ResolvedAt: d.ResolvedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// transition handles pause/resume/cancel: a guarded state change + audit.
func (a *API) transitionRollout(action string, from []string, to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		p := principalFrom(r)
		if err := a.Store.SetRolloutState(r.Context(), p.TenantID, id, from, to, time.Now()); err != nil {
			if errors.Is(err, store.ErrConflict) {
				writeErr(w, http.StatusConflict, "rollout is not "+from[0]+" (or another allowed state)")
				return
			}
			a.storeErr(w, err)
			return
		}
		a.audit(r, p, "rollout."+action, "rollout", id.String(), map[string]any{"state": to}, "success")
		w.WriteHeader(http.StatusNoContent)
	}
}

// rollbackRollout cancels the given rollout if it is still open and starts
// a new one for another version with the same targets and limits.
func (a *API) rollbackRollout(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Version string `json:"version"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p := principalFrom(r)
	old, err := a.Store.GetRollout(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	if req.Version == "" || req.Version == old.Version {
		writeErr(w, http.StatusBadRequest, "rollback needs a different version")
		return
	}
	nr := store.Rollout{
		ID: uuid.New(), Version: req.Version, GroupIDs: old.GroupIDs, BatchSize: old.BatchSize, MaxFailures: old.MaxFailures,
		State: "active", CreatedBy: "admin:" + p.Admin.Email,
	}
	if err := a.Store.ReplaceRollout(r.Context(), p.TenantID, id, nr, time.Now()); err != nil {
		a.storeErr(w, err)
		return
	}
	a.audit(r, p, "rollout.rollback", "rollout", id.String(), map[string]any{"from_version": old.Version, "to_version": nr.Version, "new_rollout_id": nr.ID.String()}, "success")
	writeJSON(w, http.StatusCreated, map[string]string{"id": nr.ID.String()})
}
