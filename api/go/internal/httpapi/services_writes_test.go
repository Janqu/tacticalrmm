package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
)

func TestServiceRestartSequence(t *testing.T) {
	ack := map[string]any{"success": true, "errormsg": ""}
	for _, tc := range []struct {
		name          string
		replies       []any
		errs          []error
		calls, status int
		failed        bool
	}{
		{"success", []any{ack, ack}, nil, 2, 200, false},
		{"stop refused", []any{map[string]any{"success": false, "errormsg": "denied"}}, nil, 1, 400, false},
		{"stop timeout", []any{nil}, []error{agentbus.ErrTimeout}, 1, 400, false},
		{"stop unavailable", []any{nil}, []error{agentbus.ErrUnavailable}, 1, 400, false},
		{"stop malformed", []any{nil}, []error{agentbus.ErrInvalidReply}, 1, 0, true},
		{"stop ambiguous", []any{map[string]any{"success": true, "errormsg": "timeout"}}, nil, 1, 400, false},
		{"start timeout", []any{ack, nil}, []error{nil, agentbus.ErrTimeout}, 2, 400, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []map[string]any
			request := func(_ context.Context, subject string, payload map[string]any, timeout time.Duration) (any, error) {
				if subject != "agent" || timeout != 32*time.Second {
					t.Fatalf("bad request subject/timeout")
				}
				index := len(got)
				got = append(got, payload)
				if index >= len(tc.replies) {
					t.Fatal("unexpected retry or restart step")
				}
				var err error
				if tc.errs != nil {
					err = tc.errs[index]
				}
				return tc.replies[index], err
			}
			status, _, err := executeServiceWrite(context.Background(), request, "agent", "Spooler", "restart", false)
			if status != tc.status || (err != nil) != tc.failed || len(got) != tc.calls {
				t.Fatalf("got status %d err %v calls %d", status, err, len(got))
			}
			for i, payload := range got {
				action := []string{"stop", "start"}[i]
				want := map[string]any{"func": "winsvcaction", "payload": map[string]any{"name": "Spooler", "action": action}}
				if !reflect.DeepEqual(payload, want) {
					t.Fatalf("payload mutated or incorrect: %#v", payload)
				}
			}
		})
	}
}

func TestServiceWriteAck(t *testing.T) {
	for _, tc := range []struct {
		reply    any
		edit, ok bool
		failure  string
	}{
		{map[string]any{"success": true, "errormsg": "timeout"}, true, true, ""},
		{map[string]any{"success": false, "errormsg": "timeout"}, true, false, "timeout"},
		{map[string]any{"success": false, "errormsg": ""}, false, false, "Something went wrong"},
		{"natsdown", true, false, "Unable to contact the agent"},
	} {
		ok, failure, err := serviceWriteAck(tc.reply, nil, tc.edit)
		if err != nil || ok != tc.ok || failure != tc.failure {
			t.Fatalf("got %v %q %v", ok, failure, err)
		}
	}
	for _, reply := range []any{nil, true, []any{}, map[string]any{}, map[string]any{"success": 1, "errormsg": ""}, map[string]any{"success": true, "errormsg": nil}} {
		if _, _, err := serviceWriteAck(reply, nil, false); err == nil {
			t.Fatalf("accepted malformed ack %#v", reply)
		}
	}
}

func TestServiceEditPayloadAndCancellation(t *testing.T) {
	calls := 0
	request := func(_ context.Context, subject string, payload map[string]any, timeout time.Duration) (any, error) {
		calls++
		want := map[string]any{"func": "editwinsvc", "payload": map[string]any{"name": "A B", "startType": "autodelay"}}
		if subject != "agent" || timeout != 10*time.Second || !reflect.DeepEqual(payload, want) {
			t.Fatal("wrong edit wire contract")
		}
		return map[string]any{"success": true, "errormsg": ""}, nil
	}
	status, _, err := executeServiceWrite(context.Background(), request, "agent", "A B", "autodelay", true)
	if err != nil || status != 200 || calls != 1 {
		t.Fatalf("got %d %v calls%d", status, err, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = executeServiceWrite(ctx, request, "agent", "A B", "restart", false)
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("canceled restart published command")
	}
}
