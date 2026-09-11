package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"freelocker/internal/appcontrol/rules"
	"freelocker/internal/server/store"
)

type approvalJSON struct {
	ID          string     `json:"id"`
	PolicyID    string     `json:"policy_id"`
	PolicyName  string     `json:"policy_name"`
	SHA256      string     `json:"sha256"`
	Path        string     `json:"path"`
	Signer      string     `json:"signer"`
	Status      string     `json:"status"`
	DeviceCount int        `json:"device_count"`
	EventCount  int64      `json:"event_count"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	DecidedAt   *time.Time `json:"decided_at"`
}

func (a *API) listApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "approved", "denied":
	default:
		writeErr(w, http.StatusBadRequest, "status must be pending, approved, or denied")
		return
	}
	reqs, err := a.Store.ListApprovalRequests(r.Context(), principalFrom(r).TenantID, status, queryInt(r, "limit", 200, 1000))
	if err != nil {
		a.storeErr(w, err)
		return
	}
	out := make([]approvalJSON, 0, len(reqs))
	for _, q := range reqs {
		out = append(out, approvalJSON{
			ID: q.ID.String(), PolicyID: q.PolicyID.String(), PolicyName: q.PolicyName,
			SHA256: q.SHA256, Path: q.Path, Signer: q.Signer, Status: q.Status,
			DeviceCount: q.DeviceCount, EventCount: q.EventCount,
			FirstSeen: q.FirstSeen, LastSeen: q.LastSeen, DecidedAt: q.DecidedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) countApprovals(w http.ResponseWriter, r *http.Request) {
	n, err := a.Store.CountPendingApprovals(r.Context(), principalFrom(r).TenantID)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"pending": n})
}

func (a *API) approveApproval(w http.ResponseWriter, r *http.Request) {
	a.decideApproval(w, r, "approved")
}

func (a *API) denyApproval(w http.ResponseWriter, r *http.Request) {
	a.decideApproval(w, r, "denied")
}

// decideApproval resolves a pending request. Approving first adds the hash
// as an allow rule on the request's policy; if that fails the request stays
// pending and can be retried.
func (a *API) decideApproval(w http.ResponseWriter, r *http.Request, status string) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p := principalFrom(r)
	req, err := a.Store.GetApprovalRequest(r.Context(), p.TenantID, id)
	if err != nil {
		a.storeErr(w, err)
		return
	}
	if req.Status != "pending" {
		writeErr(w, http.StatusConflict, "request already decided")
		return
	}
	if status == "approved" {
		norm, err := rules.Normalize(rules.Rule{
			Kind: rules.Hash, Value: req.SHA256,
			Description: fmt.Sprintf("approved from request %s (%s)", req.ID, req.Path),
		})
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := a.addHashRule(r.Context(), p, req.PolicyID, norm); err != nil {
			a.storeErr(w, err)
			return
		}
	}
	err = a.Store.DecideApprovalRequest(r.Context(), p.TenantID, id, status, p.Admin.ID, time.Now())
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "request already decided")
		return
	}
	if err != nil {
		a.storeErr(w, err)
		return
	}
	action := "approval.approve"
	if status == "denied" {
		action = "approval.deny"
	}
	a.audit(r, p, action, "approval", id.String(), map[string]any{
		"policy_id": req.PolicyID.String(), "sha256": req.SHA256,
	}, "success")
	w.WriteHeader(http.StatusNoContent)
}
