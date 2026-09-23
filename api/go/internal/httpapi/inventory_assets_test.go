package httpapi

import (
	"encoding/json"
	"testing"
	"time"
)

func TestInventoryAssetResponse(t *testing.T) {
	now := time.Now().UTC()
	row := map[string]any{"id": json.Number("7"), "site_id": json.Number("1"), "profile_id": json.Number("2"), "profile_name": "Profile", "profile_defaults": map[string]any{"owner": "default", "color": "red"}, "attributes": map[string]any{"owner": "local"}, "warranty_notified_for": "secret-internal",
		"agent_data": map[string]any{"agent_id": "abc", "hostname": "PC1", "plat": "linux", "wmi_detail": map[string]any{"make_model": "Dell", "serialnumber": "123"}, "offline_time": json.Number("5"), "overdue_time": json.Number("30"), "last_seen": now.Format(time.RFC3339Nano)}}
	result := inventoryAssetResponse(row, now)
	if _, ok := result["warranty_notified_for"]; ok {
		t.Fatal("internal column leaked")
	}
	if _, ok := result["agent_data"]; ok {
		t.Fatal("raw source leaked")
	}
	if result["agent"] != "abc" || result["agent_id"] != "abc" {
		t.Fatal("agent must be public ID")
	}
	effective := result["effective_attributes"].(map[string]any)
	if effective["owner"] != "local" || effective["color"] != "red" {
		t.Fatal("profile merge precedence incorrect")
	}
	detected := result["detected"].(map[string]any)
	if detected["status"] != "online" || detected["model"] != "Dell" || detected["serial"] != "123" {
		t.Fatalf("wrong detected: %v", detected)
	}
	delete(row, "agent_data")
	row["profile_id"] = nil
	result = inventoryAssetResponse(row, now)
	if _, ok := result["agent_id"]; ok {
		t.Fatal("absent agent must omit agent_id")
	}
	if _, ok := result["profile_name"]; ok {
		t.Fatal("absent profile must omit profile_name")
	}
	if len(result["detected"].(map[string]any)) != 0 {
		t.Fatal("unlinked asset has no detected data")
	}
}
