package httpapi

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAlertNumericValidation(t *testing.T) {
	for _, raw := range []string{`-9223372036854775808`, `"9223372036854775807"`, `" -3.0 "`, `2.0`, `null`} {
		if _, problem := alertRetcode(json.RawMessage(raw)); problem != nil {
			t.Errorf("%s: %v", raw, problem)
		}
	}
	for _, raw := range []string{`9223372036854775808`, `-9223372036854775809`, `true`, `1.5`, `"bad"`, `[]`} {
		if _, problem := alertRetcode(json.RawMessage(raw)); problem == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, raw := range []string{`null`, `[]`, `"bad"`, `99999999999999999999999999999`} {
		if _, err := alertSnoozeUntil(json.RawMessage(raw)); err == nil {
			t.Errorf("accepted snooze %s", raw)
		}
	}
	now := time.Now().UTC()
	until, err := alertSnoozeUntil(json.RawMessage(`1.9`))
	if err != nil || until.Sub(now) < 24*time.Hour || until.Sub(now) > 24*time.Hour+time.Second {
		t.Fatal(until, err)
	}
}
