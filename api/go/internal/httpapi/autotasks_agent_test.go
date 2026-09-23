package httpapi

import (
	"encoding/json"
	"testing"
)

func TestAgentTaskResultProjection(t *testing.T) {
	row, err := decodeRow([]byte(`{"id":2,"task_id":7,"agent_id":3,"last_run":"2024-01-02T13:04:05.1234+00:00","locked_at":null,"retcode":9007199254740993,"stdout":"one\n"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := serializeTaskResult(row); err != nil {
		t.Fatal(err)
	}
	if row["task"] != json.Number("7") || row["agent"] != json.Number("3") || row["retcode"] != json.Number("9007199254740993") || row["last_run"] != "2024-01-02T13:04:05.123400Z" {
		t.Fatalf("bad projection: %#v", row)
	}
	if _, ok := row["task_id"]; ok {
		t.Fatal("raw FK exposed")
	}
	if _, ok := row["agent_id"]; ok {
		t.Fatal("raw FK exposed")
	}
}
