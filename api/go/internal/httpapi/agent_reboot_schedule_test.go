package httpapi

import (
	"reflect"
	"regexp"
	"testing"
	"time"
)

func TestScheduledRebootDate(t *testing.T) {
	for _, text := range []string{"2099-1-2T3:4", "2099-01-02T03:04", "2024-02-29T23:59"} {
		if _, err := scheduledRebootDate(text); err != nil {
			t.Fatalf("rejected %q: %v", text, err)
		}
	}
	for _, text := range []string{"", "2099-01-02 03:04", "2099-01-02T03:04:00", "2099-01-02T03:04Z", "0000-01-01T00:00", "2023-02-29T00:00", "2099-13-01T00:00", "2099-01-01T24:00", "2099-01-01T00:60", "9999-12-31T23:59", "2099-01-02T03:04\n"} {
		if _, err := scheduledRebootDate(text); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
}

func TestScheduledRebootPayload(t *testing.T) {
	wall := time.Date(2099, 12, 31, 23, 58, 0, 0, time.UTC)
	want := map[string]any{"func": "schedtask", "schedtaskpayload": map[string]any{
		"type": "schedreboot", "enabled": true, "delete_expired_task_after": true,
		"start_when_available": false, "multiple_instances": 2, "trigger": "runonce", "name": "fixture",
		"start_year": 2099, "start_month": 12, "start_day": 31, "start_hour": 23, "start_min": 58,
		"expire_year": 2100, "expire_month": 1, "expire_day": 1, "expire_hour": 0, "expire_min": 3,
	}}
	if got := scheduledRebootPayload(wall, "fixture"); !reflect.DeepEqual(got, want) {
		t.Fatalf("wrong scheduler payload: %#v", got)
	}
	zone, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ wall, utc string }{
		{"2099-03-29T02:30", "2099-03-29T01:30:00Z"},
		{"2099-10-25T02:30", "2099-10-25T00:30:00Z"},
	} {
		wall, err := scheduledRebootDate(tc.wall)
		if err != nil {
			t.Fatal(err)
		}
		due, err := pendingWallTime(wall.Format("2006-01-02 15:04:05"), zone)
		if err != nil || due.Format(time.RFC3339) != tc.utc {
			t.Fatalf("DST resolution %s got %s %v", tc.wall, due, err)
		}
	}
}

func TestScheduledRebootName(t *testing.T) {
	pattern := regexp.MustCompile(`^TacticalRMM_SchedReboot_[a-zA-Z]{10}$`)
	for range 10 {
		name, err := scheduledRebootName()
		if err != nil || !pattern.MatchString(name) {
			t.Fatalf("invalid task name %q %v", name, err)
		}
	}
}
