package notify_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"

	"freelocker/internal/server/config"
	"freelocker/internal/server/notify"
)

// fakeSMTP speaks just enough SMTP (no TLS, no auth) to capture one message.
func fakeSMTP(t *testing.T) (addr string, got *strings.Builder) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = &strings.Builder{}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := func(s string) { conn.Write([]byte(s + "\r\n")) }
		w("220 fake ESMTP")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					w("250 queued")
					continue
				}
				got.WriteString(line + "\n")
				continue
			}
			got.WriteString("> " + line + "\n")
			switch {
			case strings.HasPrefix(line, "EHLO"):
				w("250-fake")
				w("250 8BITMIME")
			case strings.HasPrefix(line, "HELO"):
				w("250 fake")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				w("250 ok")
			case line == "DATA":
				w("354 go")
				inData = true
			case line == "QUIT":
				w("221 bye")
				return
			default:
				w("250 ok")
			}
		}
	}()
	return ln.Addr().String(), got
}

func TestSMTPMailerPlain(t *testing.T) {
	addr, got := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	m := notify.NewSMTPMailer(config.SMTP{Host: host, Port: p, From: "FreeLocker <fl@example.com>", STARTTLS: false})
	if err := m.Send(context.Background(), []string{"a@example.com", "b@example.com"}, "[FreeLocker] hi", "line one\nline two"); err != nil {
		t.Fatal(err)
	}
	s := got.String()
	for _, want := range []string{"> MAIL FROM:<fl@example.com>", "> RCPT TO:<a@example.com>", "> RCPT TO:<b@example.com>", "Subject: [FreeLocker] hi", "To: a@example.com, b@example.com", "line two"} {
		if !strings.Contains(s, want) {
			t.Errorf("transcript missing %q:\n%s", want, s)
		}
	}
}
