package httpapi

import (
	"context"
	"errors"
	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"testing"
	"time"
)

func TestRunChecksResponse(t *testing.T) {
	cases := []struct {
		reply  any
		err    error
		status int
		body   string
	}{
		{"ok", nil, 200, "Checks will now be run on Host"}, {"busy", nil, 400, "Checks are already running on Host"},
		{map[string]any{"ok": true}, nil, 400, "Unable to contact the agent"}, {"ok", agentbus.ErrTimeout, 400, "Unable to contact the agent"}, {nil, agentbus.ErrInvalidReply, 400, "Unable to contact the agent"},
	}
	for _, tc := range cases {
		status, body := runChecksResponse(tc.reply, tc.err, "Host")
		if status != tc.status || body != tc.body {
			t.Fatalf("%v: %d %q", tc.reply, status, body)
		}
	}
}
func TestPingInvalidReplyAndCancellation(t *testing.T) {
	calls := 0
	request := func(ctx context.Context, subject string, payload map[string]any, timeout time.Duration) (any, error) {
		calls++
		if subject != "target" || payload["func"] != "ping" || timeout != 2*time.Second {
			t.Fatal("wrong request")
		}
		return map[string]any{}, nil
	}
	status, err := pingAgentStatus(context.Background(), request, "target")
	if err != nil || status != "offline" || calls != 1 {
		t.Fatalf("%s %v calls=%d", status, err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = pingAgentStatus(ctx, request, "target")
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("canceled ping sent command")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	_, err = pingAgentStatus(ctx, func(context.Context, string, map[string]any, time.Duration) (any, error) {
		cancel()
		return nil, agentbus.ErrTimeout
	}, "target")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("sleep ignored cancellation: %v", err)
	}
}
