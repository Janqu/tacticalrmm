package httpapi

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestScriptWriteValidation(t *testing.T) {
	body := "  if ($true) {\n    Write-Host test\n  }\n"
	raw, _ := json.Marshal(body)
	value, problem := scriptBodySpec(raw)
	if problem != nil || value != body {
		t.Fatalf("body whitespace lost: %q %v", value, problem)
	}
	value, problem = scriptArraySpec(false)(json.RawMessage(`[" x ",null,""]`))
	if problem != nil || !reflect.DeepEqual(value, []any{"x", nil, ""}) {
		t.Fatalf("array: %#v %v", value, problem)
	}
	_, problem = scriptArraySpec(true)(json.RawMessage(`[null,"", "xxxxxxxxxxxxxxxxxxxxx"]`))
	if len(problem.(map[string][]string)) != 3 {
		t.Fatalf("platform errors: %v", problem)
	}
	values, err := parseFields(map[string]json.RawMessage{"name": json.RawMessage(`" test "`), "script_type": json.RawMessage(`"builtin"`), "id": json.RawMessage(`9`)}, scriptParsers())
	if err != nil || !reflect.DeepEqual(values, map[string]any{"name": "test"}) {
		t.Fatalf("read-only fields: %v %v", values, err)
	}
}
