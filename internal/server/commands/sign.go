package commands

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	flv1 "freelocker/gen/freelocker/v1"

	"google.golang.org/protobuf/proto"
)

const clockSkew = 5 * time.Minute

var typeNames = map[flv1.CommandType]string{
	flv1.CommandType_COMMAND_TYPE_PING:               "ping",
	flv1.CommandType_COMMAND_TYPE_REFRESH_INVENTORY:  "refresh_inventory",
	flv1.CommandType_COMMAND_TYPE_ROTATE_CERTIFICATE: "rotate_certificate",
	flv1.CommandType_COMMAND_TYPE_UNINSTALL:          "uninstall",
	flv1.CommandType_COMMAND_TYPE_UPDATE_AGENT:       "update_agent",
}

func TypeName(t flv1.CommandType) string { return typeNames[t] }

func ParseType(name string) (flv1.CommandType, error) {
	for t, n := range typeNames {
		if n == name {
			return t, nil
		}
	}
	return flv1.CommandType_COMMAND_TYPE_UNSPECIFIED, fmt.Errorf("unknown command type %q", name)
}

func Sign(key ed25519.PrivateKey, c *flv1.Command) (*flv1.SignedCommand, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	if err != nil {
		return nil, err
	}
	return &flv1.SignedCommand{Command: b, Signature: ed25519.Sign(key, b)}, nil
}

func Verify(pub ed25519.PublicKey, sc *flv1.SignedCommand, deviceID string, now time.Time) (*flv1.Command, error) {
	if !ed25519.Verify(pub, sc.GetCommand(), sc.GetSignature()) {
		return nil, errors.New("bad command signature")
	}
	c := &flv1.Command{}
	if err := proto.Unmarshal(sc.GetCommand(), c); err != nil {
		return nil, err
	}
	if c.GetDeviceId() != deviceID {
		return nil, errors.New("command addressed to another device")
	}
	if now.After(time.Unix(c.GetExpiresAtUnix(), 0).Add(clockSkew)) {
		return nil, errors.New("command expired")
	}
	return c, nil
}
