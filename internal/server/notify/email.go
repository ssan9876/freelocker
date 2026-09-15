package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"sort"
	"strings"
	"time"

	"freelocker/internal/server/config"
)

type Mailer interface {
	Send(ctx context.Context, to []string, subject, body string) error
}

type smtpMailer struct{ cfg config.SMTP }

func NewSMTPMailer(cfg config.SMTP) Mailer { return &smtpMailer{cfg: cfg} }

func (m *smtpMailer) Send(ctx context.Context, to []string, subject, body string) error {
	cfg := m.cfg
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	fromAddr := cfg.From
	if a, err := mail.ParseAddress(cfg.From); err == nil {
		fromAddr = a.Address
	}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	d := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if cfg.Port == 465 {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if cfg.Port != 465 && cfg.STARTTLS {
		if err := c.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(fromAddr); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := "From: " + cfg.From + "\r\n" +
		"To: " + strings.Join(to, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
		strings.ReplaceAll(body, "\n", "\r\n")
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// formatEmailBody renders the event body followed by its detail map.
func formatEmailBody(e Event) string {
	var b strings.Builder
	b.WriteString(e.Body)
	b.WriteString("\n\n")
	keys := make([]string, 0, len(e.Detail))
	for k := range e.Detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %v\n", k, e.Detail[k])
	}
	fmt.Fprintf(&b, "\nEvent: %s at %s\n", e.Kind, e.At.UTC().Format(time.RFC3339))
	return b.String()
}
