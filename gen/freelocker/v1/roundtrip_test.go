package flv1_test

import (
	"testing"

	flv1 "freelocker/gen/freelocker/v1"

	"google.golang.org/protobuf/proto"
)

func TestAgentMessageRoundtrip(t *testing.T) {
	in := &flv1.AgentMessage{Body: &flv1.AgentMessage_Heartbeat{Heartbeat: &flv1.Heartbeat{
		Inventory:  &flv1.Inventory{Hostname: "pc-01", IpAddresses: []string{"10.0.0.5"}},
		SentAtUnix: 1700000000,
	}}}
	b, err := proto.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	out := &flv1.AgentMessage{}
	if err := proto.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
	if got := out.GetHeartbeat().GetInventory().GetHostname(); got != "pc-01" {
		t.Fatalf("hostname = %q, want pc-01", got)
	}
}
