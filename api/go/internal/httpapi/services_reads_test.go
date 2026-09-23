package httpapi

import (
	"errors"
	"reflect"
	"testing"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
)

func TestServiceReadResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		detail bool
		reply  any
		err    error
		status int
		want   any
	}{
		{"list", false, []any{}, nil, 200, []any{}},
		{"null", false, nil, nil, 200, nil},
		{"list down", false, "natsdown", nil, 400, "Unable to contact the agent"},
		{"detail down", true, "natsdown", nil, 200, "natsdown"},
		{"detail unavailable", true, nil, agentbus.ErrUnavailable, 200, "natsdown"},
		{"list unavailable", false, nil, agentbus.ErrUnavailable, 400, "Unable to contact the agent"},
		{"detail timeout", true, nil, agentbus.ErrTimeout, 400, "Unable to contact the agent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body, err := serviceReadResponse(tc.reply, tc.err, tc.detail)
			if err != nil || status != tc.status || !reflect.DeepEqual(body, tc.want) {
				t.Fatalf("got %d %#v %v", status, body, err)
			}
		})
	}
	for _, err := range []error{agentbus.ErrInvalidReply, errors.New("request canceled")} {
		if _, _, got := serviceReadResponse(nil, err, false); got == nil {
			t.Fatal("transport error suppressed")
		}
	}
}
