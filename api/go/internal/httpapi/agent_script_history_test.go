package httpapi

import (
	"encoding/json"
	"testing"
)

func TestScriptHistoryLimit(t *testing.T) {
	for raw, want := range map[string]int{"0": 0, " +001_2 ": 12, "١٢": 12} {
		got, ok := scriptHistoryLimit(raw)
		if !ok || got != want {
			t.Fatal(raw, got, ok)
		}
	}
	for _, raw := range []string{"-1", "x", "1.5", "1__2", "99999999999999999999999999999"} {
		if _, ok := scriptHistoryLimit(raw); ok {
			t.Fatal(raw)
		}
	}
}
func TestScriptHistoryProjection(t *testing.T) {
	row := historyRow{ID: 1, Agent: 2, Username: "system", ScriptResults: json.RawMessage(`{"large":18446744073709551615}`)}
	out := scriptHistoryEntry(row, "agent")
	if _, exists := out["script_name"]; exists {
		t.Fatal("null script must omit name")
	}
	if len(out) != 7 {
		t.Fatal(out)
	}
	encoded, err := json.Marshal(out)
	if err != nil || len(encoded) == 0 {
		t.Fatal(err)
	}
	for _, raw := range []string{"2025-01-02", "2025-01-02T03:04:05+02:00", "2025-01-02T03:04:05.123456Z"} {
		if _, ok := scriptHistoryDate(raw); !ok {
			t.Fatal(raw)
		}
	}
	for _, raw := range []string{"invalid", "2025-02-30"} {
		if _, ok := scriptHistoryDate(raw); ok {
			t.Fatal(raw)
		}
	}
}
