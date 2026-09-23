package httpapi

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gofiber/fiber/v3"
)

func TestSNMPBuiltinPresets(t *testing.T) {
	for _, tc := range []struct {
		kind  string
		count int
	}{{"", 3}, {"switch", 1}, {"server", 2}, {"printer", 0}, {"unknown", 0}} {
		presets := builtinSNMPPresets(tc.kind)
		if len(presets) != tc.count {
			t.Fatalf("%s: got %d", tc.kind, len(presets))
		}
		for _, value := range presets {
			p := value.(fiber.Map)
			if tc.kind != "" && p["device_type"] != tc.kind {
				t.Fatal("wrong device type")
			}
		}
	}
	p := builtinSNMPPresets("server")[0].(fiber.Map)
	if p["metric_map"].(fiber.Map)["health.overall"].(fiber.Map)["oid"] != "1.3.6.1.4.1.232.6.1.3" {
		t.Fatal("iLO overall OID changed")
	}
	if _, present := builtinSNMPPresets("switch")[0].(fiber.Map)["built_in"]; present {
		t.Fatal("USW fields must match Python preset")
	}
}

func TestSNMPProbeReadiness(t *testing.T) {
	body, err := os.ReadFile("../../../tacticalrmm/qdt_snmp/probe/snmp_probe.py")
	if err != nil {
		t.Fatal(err)
	}
	if !snmpProbeScriptCurrent(string(body)) || snmpProbeScriptCurrent(string(body)+"\n") {
		t.Fatal("update snmpProbeSHA256 when the shipped remote-agent script changes")
	}
	for _, tc := range []struct {
		actions string
		want    bool
	}{
		{`[{"script_args":["--key","{{global.snmp_api_key_3}}"]}]`, true},
		{`[{"script_args":["{{global.snmp_api_key_4}}"]}]`, false},
		{`[{"script_args":"{{global.snmp_api_key_3}}"}]`, false},
		{`[{"script_args":[{"secret":"unused"}]}]`, false},
		{`[{"script_args":["{{global.snmp_api_key_3}}"]},{}]`, false},
		{`null`, false}, {`{}`, false}, {`[]`, false},
	} {
		if got := snmpProbeArgsReady(json.RawMessage(tc.actions), 3); got != tc.want {
			t.Fatalf("%s: got %v", tc.actions, got)
		}
	}
}
