package commands

import (
	"context"
	"encoding/json"

	flv1 "freelocker/gen/freelocker/v1"

	"github.com/google/uuid"
)

type UpdatePayload struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    []byte `json:"sha256"`
	Signature []byte `json:"signature"`
}

func MarshalUpdate(p UpdatePayload) []byte {
	b, _ := json.Marshal(p)
	return b
}

func ParseUpdate(b []byte) (UpdatePayload, error) {
	var p UpdatePayload
	err := json.Unmarshal(b, &p)
	return p, err
}

func (s *Service) IssueUpdate(ctx context.Context, tenantID, deviceID uuid.UUID, p UpdatePayload, actor string) (uuid.UUID, error) {
	return s.Issue(ctx, tenantID, deviceID, flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT, MarshalUpdate(p), nil, actor)
}
