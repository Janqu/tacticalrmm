package httpapi

import (
	"reflect"
	"testing"
	"time"
)

func TestEventLogPayload(t *testing.T) {
	for _, tc := range []struct {
		name, raw, days string
		timeout         int
	}{
		{"Security", "0007", "7", 180}, {"security", "0", "0", 30},
		{"Application", "18446744073709551616000", "18446744073709551616000", 30},
		{"Arbitrary Ä log", "000", "0", 30},
	} {
		payload, duration, err := eventLogPayload(tc.name, tc.raw)
		want := map[string]any{"func": "eventlog", "timeout": tc.timeout, "payload": map[string]any{"logname": tc.name, "days": tc.days}}
		if err != nil || duration != time.Duration(tc.timeout+2)*time.Second || !reflect.DeepEqual(payload, want) {
			t.Fatalf("got %#v %s %v", payload, duration, err)
		}
	}
	for _, invalid := range []string{"", "-1", "+1", "1.0", "１", "1 "} {
		if _, _, err := eventLogPayload("System", invalid); err == nil {
			t.Fatalf("accepted invalid days %q", invalid)
		}
	}
}
