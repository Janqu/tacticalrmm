package httpapi

import (
	"encoding/json"
	"testing"
)

func TestSoftwareJSONPreservesPayload(t *testing.T) {
	raw := json.RawMessage(`{"id":9007199254740993,"agent":3,"software":{"items":[null,true,"ü"],"bytes":18446744073709551615}}`)
	data, err := json.Marshal(installedSoftwareResponse([]json.RawMessage{raw}, true))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(raw) {
		t.Fatalf("payload changed: %s", data)
	}
	for _, rows := range [][]json.RawMessage{{}, {raw, raw}} {
		data, err := json.Marshal(installedSoftwareResponse(rows, true))
		if err != nil || string(data) != "[]" {
			t.Fatalf("missing/duplicate software result: %s %v", data, err)
		}
	}
	data, err = json.Marshal(installedSoftwareResponse([]json.RawMessage{raw}, false))
	if err != nil || string(data) != "["+string(raw)+"]" {
		t.Fatalf("list shape: %s %v", data, err)
	}
}
