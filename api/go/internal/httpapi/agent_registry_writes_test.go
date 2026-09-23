package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
)

func TestRegistryWritePayload(t *testing.T) {
	var input map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{"path":" HKLM\\Software ","name":"  value  ","type":" reg_qword ","data":{"nested":[18446744073709551615,null,true]}}`), &input); err != nil {
		t.Fatal(err)
	}
	payload, failure, err := registryWritePayload("create-value", input)
	if err != nil || failure != "" || payload["path"] != `HKLM\Software` || payload["name"] != "  value  " || payload["type"] != "REG_QWORD" {
		t.Fatalf("got %#v %q %v", payload, failure, err)
	}
	if payload["data"].(map[string]any)["nested"].([]any)[0] != uint64(18446744073709551615) {
		t.Fatal("large integer lost precision")
	}
	input["data"] = json.RawMessage(`18446744073709551616`)
	if _, _, err := registryWritePayload("create-value", input); err == nil {
		t.Fatal("unrepresentable number accepted")
	}
	input["path"] = json.RawMessage(`42`)
	if _, _, err := registryWritePayload("create-value", input); err == nil {
		t.Fatal("numeric path accepted")
	}
	input["path"] = json.RawMessage(`null`)
	if _, failure, err := registryWritePayload("create-value", input); err != nil || failure != "Registry path is required" {
		t.Fatal("null path required semantics changed")
	}
	for _, action := range []string{"create-value", "modify-value"} {
		input = map[string]json.RawMessage{"path": json.RawMessage(`"HKLM"`)}
		_, failure, _ := registryWritePayload(action, input)
		want := "Registry value type is required"
		if action == "modify-value" {
			want = "Registry value name is required"
		}
		if failure != want {
			t.Fatalf("wrong validation order %s", failure)
		}
	}
}

func TestRegistryWriteResponse(t *testing.T) {
	payload := map[string]any{"path": "HKLM", "name": "value", "type": "REG_SZ", "data": "old"}
	for _, action := range []string{"create-key", "delete-key", "rename-key", "delete-value", "create-value", "modify-value", "rename-value"} {
		status, _ := registryWriteResponse(action, payload, "ok", nil)
		want := 200
		if action == "create-value" || action == "modify-value" || action == "rename-value" {
			want = 502
		}
		if status != want {
			t.Fatalf("%s got%d", action, status)
		}
		for _, bad := range []any{"nonsense", nil, true, []any{}} {
			if status, _ := registryWriteResponse(action, payload, bad, nil); status != 502 {
				t.Fatalf("accepted malformed ack %#v", bad)
			}
		}
	}
	status, body := registryWriteResponse("create-value", payload, map[string]any{"name": nil, "data": nil}, nil)
	if status != 200 || body.(map[string]any)["data"].(map[string]any)["name"] != nil {
		t.Fatal("explicit null override lost")
	}
	status, body = registryWriteResponse("rename-key", payload, map[string]any{"error": false}, nil)
	if status != 400 || body != "Registry Rename Key failed: False" {
		t.Fatalf("wrong error response %d %#v", status, body)
	}
	for _, err := range []error{agentbus.ErrTimeout, agentbus.ErrUnavailable} {
		if status, _ := registryWriteResponse("create-key", payload, nil, err); status != 400 {
			t.Fatal("transport failure accepted")
		}
	}
}
