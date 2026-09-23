package httpapi

import (
	"encoding/json"
	"testing"
)

func TestAlertQueryInteger(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want int64
	}{{`" 2 "`, 2}, {`2.9`, 2}, {`true`, 1}, {`false`, 0}, {`-1`, -1}} {
		got, ok := alertQueryInteger(json.RawMessage(test.raw))
		if !ok || got != test.want {
			t.Errorf("%s: %d %v", test.raw, got, ok)
		}
	}
	for _, raw := range []string{`null`, `[]`, `"2.0"`, `9223372036854775808`, `-9223372036854775809`, `1e100`} {
		if _, ok := alertQueryInteger(json.RawMessage(raw)); ok {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestAlertNullAgentProjection(t *testing.T) {
	row, err := serializeAlertRow(map[string]any{"agent_id": nil, "assigned_check_id": nil, "assigned_task_id": nil, "alert_time": "2024-01-02T03:04:05.1234Z"}, alertAgentNames{})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := row["agent_id"]; exists {
		t.Fatal("null relation exposed computed agent_id")
	}
	if row["agent"] != nil || *row["alert_time"].(*string) != "2024-01-02T03:04:05.123400Z" {
		t.Fatal(row)
	}
}
