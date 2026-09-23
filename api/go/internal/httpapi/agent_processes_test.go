package httpapi

import (
	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"math"
	"testing"
)

func TestProcessCommandReplyAndPID(t *testing.T) {
	for _, raw := range []string{"0", "00042", "18446744073709551615"} {
		if _, err := parseProcessPID(raw); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{"-1", "1.5", "18446744073709551616", ""} {
		if _, err := parseProcessPID(raw); err == nil {
			t.Fatalf("invalid PID accepted %q", raw)
		}
	}
	status, body := processCommandResponse("ok", nil, true, 42)
	if status != 200 || body != "Process with PID: 42 was ended successfully" {
		t.Fatal(status, body)
	}
	status, body = processCommandResponse("permission denied", nil, true, 42)
	if status != 400 || body != "permission denied" {
		t.Fatal(status, body)
	}
	for _, tc := range []struct {
		reply any
		err   error
		kill  bool
		want  int
	}{
		{[]any{map[string]any{"pid": uint64(9007199254740993)}}, nil, false, 200},
		{[]any{}, nil, false, 200}, {nil, agentbus.ErrTimeout, true, 400}, {"natsdown", nil, false, 400},
		{map[string]any{}, nil, true, 502}, {[]any{"bad"}, nil, false, 502}, {[]any{map[string]any{"cpu": math.NaN()}}, nil, false, 502},
		{nil, agentbus.ErrInvalidReply, false, 502},
	} {
		status, _ := processCommandResponse(tc.reply, tc.err, tc.kill, 42)
		if status != tc.want {
			t.Fatalf("%#v: got%d want%d", tc.reply, status, tc.want)
		}
	}
}
