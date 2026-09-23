package httpapi

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestInheritedCheckPrecedenceAndGrouping(t *testing.T) {
	agent := int64(1)
	script := int64(9)
	ip := "192.0.2.1"
	disk := "C:"
	log := "Application"
	event := int64(17)
	direct := []inheritedCheck{{ID: 1, Agent: &agent, Type: "ping", IP: &ip}, {ID: 2, Agent: &agent, Type: "memory"}}
	byPolicy := map[int64][]inheritedCheck{
		10: {{ID: 10, Type: "ping", IP: &ip}, {ID: 11, Type: "eventlog", LogName: &log, EventID: &event}, {ID: 12, Type: "script", Script: &script, Platforms: json.RawMessage(`["windows"]`)}},
		20: {{ID: 20, Type: "memory"}, {ID: 21, Type: "diskspace", Disk: &disk}, {ID: 22, Type: "eventlog", LogName: &log, EventID: &event}},
	}
	policies := []agentInheritedPolicy{{ID: 20}, {ID: 10, Enforced: true}}
	got, flags, err := selectInheritedChecks(direct, byPolicy, policies, "windows")
	if err != nil || !reflect.DeepEqual(got, []int64{21, 10, 12, 11}) || !reflect.DeepEqual(flags, []int64{1}) {
		t.Fatalf("%v %v %v", got, flags, err)
	}
	got, flags, err = selectInheritedChecks(direct, byPolicy, policies, "linux")
	if err != nil || !reflect.DeepEqual(got, []int64{10}) || !reflect.DeepEqual(flags, []int64{1}) {
		t.Fatalf("linux: %v %v %v", got, flags, err)
	}
	got, flags, err = selectInheritedChecks(direct, byPolicy, nil, "windows")
	if err != nil || len(got) != 0 || len(flags) != 0 {
		t.Fatalf("no active policies: %v %v %v", got, flags, err)
	}
}
