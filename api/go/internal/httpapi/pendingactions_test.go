package httpapi

import (
	"testing"
	"time"
)

func TestPendingWallTimeFoldZero(t *testing.T) {
	for _, test := range []struct{ zone, wall, utc string }{
		{"Europe/Berlin", "2024-10-27 02:30:00", "2024-10-27T00:30:00Z"},
		{"Europe/Berlin", "2024-03-31 02:30:00", "2024-03-31T01:30:00Z"},
		{"America/New_York", "2024-11-03 01:30:00", "2024-11-03T05:30:00Z"},
		{"America/New_York", "2024-03-10 02:30:00", "2024-03-10T07:30:00Z"},
		{"Asia/Kathmandu", "2024-1-2 12:0:0", "2024-01-02T06:15:00Z"},
	} {
		zone, err := time.LoadLocation(test.zone)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pendingWallTime(test.wall, zone)
		if err != nil || got.Format(time.RFC3339) != test.utc {
			t.Errorf("%s %s: %s %v", test.zone, test.wall, got, err)
		}
	}
	for _, text := range []string{"bad", "2024-02-30 12:00:00", "0000-01-01 00:00:00"} {
		if _, err := pendingWallTime(text, time.UTC); err == nil {
			t.Errorf("accepted %s", text)
		}
	}
}

func TestPendingTaskName(t *testing.T) {
	for _, value := range []any{nil, 42, "", "   ", []any{"task"}} {
		if _, err := pendingTaskName(map[string]any{"details": map[string]any{"taskname": value}}); err == nil {
			t.Errorf("accepted %#v", value)
		}
	}
	if _, err := pendingTaskName(map[string]any{}); err == nil {
		t.Fatal("accepted missing details")
	}
	got, err := pendingTaskName(map[string]any{"details": map[string]any{"taskname": "  actual task  "}})
	if err != nil || got != "  actual task  " {
		t.Fatal(got, err)
	}
}
