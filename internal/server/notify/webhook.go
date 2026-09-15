package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Sign returns the X-FreeLocker-Signature value for body.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) postWebhook(ctx context.Context, url string, secret []byte, e Event, deliveryID string) error {
	body, err := json.Marshal(e)
	if err != nil {
		return permanentError{"marshal: " + err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return permanentError{"bad url: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "FreeLocker-Notify/1")
	req.Header.Set("X-FreeLocker-Event", e.Kind)
	req.Header.Set("X-FreeLocker-Delivery", deliveryID)
	if len(secret) > 0 {
		req.Header.Set("X-FreeLocker-Signature", Sign(secret, body))
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
