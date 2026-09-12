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
	ID             string     `json:"id"`
	PolicyID       string     `json:"policy_id"`
	PolicyName     string     `json:"policy_name"`
	SHA256         string     `json:"sha256"`
	Path           string     `json:"path"`
	Signer         string     `json:"signer"`
	SignerTBS      string     `json:"signer_tbs"`
	SignerVerified bool       `json:"signer_verified"`
	Status         string     `json:"status"`
	DeviceCount    int        `json:"device_count"`
	EventCount     int64      `json:"event_count"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	DecidedAt      *time.Time `json:"decided_at"`
}

func (a *API) listApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "approved", "denied", "expired":
	default:
		writeErr(w, http.StatusBadRequest, "status must be pending, approved, denied, or expired")
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
			SHA256: q.SHA256, Path: q.Path, Signer: q.Signer,
			SignerTBS: q.SignerTBS, SignerVerified: q.SignerVerified, Status: q.Status,
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

// decideApproval resolves a pending request. Approving first adds an allow
// rule to the request's policy — by hash, path or publisher, per the optional
// "kind" body field; if that fails the request stays pending and can be
// retried.
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
	kind := rules.Hash
	if status == "approved" {
		// Approve as a hash rule (default), a path rule when a path is known,
		// or a publisher rule when the agent reported a signature Windows
		// verified — a publisher rule survives the application updating.
		value, publisher := req.SHA256, ""
		if r.Body != nil {
			var body struct {
				Kind string `json:"kind"`
			}
			_ = readJSONOptional(r, &body)
			switch body.Kind {
			case "", "hash":
			case "path":
				if req.Path == "" {
					writeErr(w, http.StatusBadRequest, "cannot approve by path: this request has no path")
					return
				}
				kind, value = rules.Path, req.Path
			case "publisher":
				if req.SignerTBS == "" || !req.SignerVerified {
					writeErr(w, http.StatusBadRequest, "cannot approve by publisher: no verified signature for this program")
					return
				}
				kind, value, publisher = rules.Publisher, req.SignerTBS, req.Signer
			default:
				writeErr(w, http.StatusBadRequest, "kind must be hash, path, or publisher")
				return
			}
		}
		norm, err := rules.Normalize(rules.Rule{
			Kind: kind, Value: value, PublisherName: publisher,
			Description: fmt.Sprintf("approved from request %s (%s)", req.ID, req.Path),
		})
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if _, err := a.addPolicyRule(r.Context(), p, req.PolicyID, norm); err != nil {
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
	detail := map[string]any{"policy_id": req.PolicyID.String(), "sha256": req.SHA256}
	if status == "approved" {
		detail["kind"] = string(kind)
	}
	a.audit(r, p, action, "approval", id.String(), detail, "success")
	w.WriteHeader(http.StatusNoContent)
}
