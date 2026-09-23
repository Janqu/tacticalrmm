package httpapi

import (
	"encoding/json"
	"testing"
)

func TestPlanScanUpdates(t *testing.T) {
	raw := json.RawMessage(`[{"guid":"known","downloaded":true,"installed":false},{"guid":"skip","kb_article_ids":[]},{"guid":"new","kb_article_ids":["123"],"title":"  title  ","description":null,"severity":"Important","categories":["A",null],"category_ids":[],"more_info_urls":[],"support_url":null,"revision_number":1,"installed":false,"downloaded":false},{"guid":"new","installed":true,"downloaded":true}]`)
	plan, returned, err := planScanUpdates(raw, map[string]bool{"str:known": true})
	if err != nil || len(plan) != 4 || len(returned) != 4 {
		t.Fatal(plan, returned, err)
	}
	if !plan[1].Skip || plan[2].Fields["title"] != "  title  " || plan[2].Fields["action"] != "nothing" || plan[2].Fields["result"] != "n/a" {
		t.Fatal(plan)
	}
	if _, present := plan[3].Fields["title"]; present {
		t.Fatal("duplicate new GUID must update only flags")
	}
}
func TestScanPayloadValidation(t *testing.T) {
	for _, raw := range []string{`{}`, `[null]`, `[{"guid":"known","installed":false,"downloaded":"false"}]`, `[{"guid":{}}]`, `[{"guid":"new","kb_article_ids":["123"]}]`} {
		if _, _, err := planScanUpdates(json.RawMessage(raw), map[string]bool{"str:known": true}); err == nil {
			t.Fatal("accepted", raw)
		}
	}
	for _, raw := range []string{`[{"guid":"skip"}]`, `[{"guid":"skip","kb_article_ids":null}]`, `[{"guid":"skip","kb_article_ids":[42]}]`} {
		plan, _, err := planScanUpdates(json.RawMessage(raw), map[string]bool{})
		if err != nil || len(plan) != 1 || !plan[0].Skip {
			t.Fatal(raw, plan, err)
		}
	}
}

func TestWinUpdateSuccess(t *testing.T) {
	for _, value := range []string{`true`, `false`} {
		result, err := winUpdateSuccess(map[string]json.RawMessage{"success": json.RawMessage(value)})
		if err != nil || result != (value == "true") {
			t.Fatal(value, result, err)
		}
	}
	for _, value := range []string{`null`, `"true"`, `1`, `0`, `[]`, `{}`, ``} {
		if _, err := winUpdateSuccess(map[string]json.RawMessage{"success": json.RawMessage(value)}); err == nil {
			t.Fatal("accepted", value)
		}
	}
}

func TestUpdateCompletionReboot(t *testing.T) {
	for _, policy := range []any{"never", "inherit", "unknown", nil} {
		if updateCompletionReboot(policy, false) || updateCompletionReboot(policy, true) {
			t.Fatal("unexpected reboot", policy)
		}
	}
	if !updateCompletionReboot("always", false) || !updateCompletionReboot("always", true) || updateCompletionReboot("required", false) || !updateCompletionReboot("required", true) {
		t.Fatal("incorrect reboot policy")
	}
}

func TestInstallGUIDPayload(t *testing.T) {
	known := "known"
	got := installGUIDPayload([]*string{&known, nil, &known})
	if len(got) != 3 || got[0] != "known" || got[1] != nil || got[2] != "known" {
		t.Fatal(got)
	}
	if got := installGUIDPayload(nil); got == nil || len(got) != 0 {
		t.Fatal(got)
	}
}
