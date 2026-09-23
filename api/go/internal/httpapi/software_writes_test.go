package httpapi

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
)

func TestSoftwareInstallName(t *testing.T) {
	for _, raw := range []string{"", `null`, `false`, `12`, `[]`, `{}`, `""`, `" \t "`} {
		if _, err := softwareInstallName(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted invalid name %s", raw)
		}
	}
	for _, name := range []string{"firefox", "package.with-dashes", " A+ B ", "Ä-package"} {
		raw, _ := json.Marshal(name)
		got, err := softwareInstallName(raw)
		if err != nil || got != name {
			t.Fatalf("changed or rejected valid name %q", name)
		}
	}
}

func TestSoftwareInstallAck(t *testing.T) {
	for _, tc := range []struct {
		reply             any
		err               error
		accepted, failure bool
	}{
		{"ok", nil, true, false}, {"timeout", nil, false, false},
		{"error", nil, false, false}, {nil, agentbus.ErrTimeout, false, false},
		{nil, agentbus.ErrUnavailable, false, false}, {nil, agentbus.ErrInvalidReply, false, true},
		{map[string]any{"success": true}, nil, false, true}, {nil, nil, false, true},
		{nil, errors.New("canceled"), false, true},
	} {
		accepted, err := softwareInstallAck(tc.reply, tc.err)
		if accepted != tc.accepted || (err != nil) != tc.failure {
			t.Fatalf("got %v %v for %#v/%v", accepted, err, tc.reply, tc.err)
		}
	}
}

func TestSoftwareInstallDefiniteRejection(t *testing.T) {
	if !softwareInstallRejected("denied", nil) || !softwareInstallRejected("", nil) {
		t.Fatal("explicit rejection must allow pending-only cleanup")
	}
	for _, reply := range []any{"ok", "timeout", "natsdown", nil, false, map[string]any{"error": "failed"}} {
		if softwareInstallRejected(reply, nil) {
			t.Fatalf("ambiguous reply permits deletion: %#v", reply)
		}
	}
	for _, err := range []error{agentbus.ErrTimeout, agentbus.ErrUnavailable, agentbus.ErrInvalidReply, errors.New("canceled")} {
		if softwareInstallRejected("denied", err) {
			t.Fatal("transport error permits deletion")
		}
	}
}
