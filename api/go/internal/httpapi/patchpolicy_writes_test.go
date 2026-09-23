package httpapi

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestPatchPolicyValidation(t *testing.T) {
	for _, test := range []struct {
		raw   string
		want  any
		valid bool
	}{
		{`null`, nil, true}, {`[]`, []any{}, true}, {`[0,"2","-3.0",2147483647,-2147483648]`, []any{int64(0), int64(2), int64(-3), int64(2147483647), int64(-2147483648)}, true},
		{`[null]`, nil, false}, {`[2147483648]`, nil, false}, {`[-2147483649]`, nil, false}, {`[true]`, nil, false}, {`"1"`, nil, false},
	} {
		value, problem := patchDaysSpec(json.RawMessage(test.raw))
		if (problem == nil) != test.valid || test.valid && !reflect.DeepEqual(value, test.want) {
			t.Errorf("%s: %v / %v", test.raw, value, problem)
		}
	}
	p := patchPolicyParsers()
	if _, err := parseFields(map[string]json.RawMessage{"run_time_hour": json.RawMessage(`24`)}, p); err == nil {
		t.Fatal("accepted invalid hour")
	}
	if values, err := parseFields(map[string]json.RawMessage{"run_time_hour": json.RawMessage(`"23"`), "run_time_day": json.RawMessage(`31`)}, p); err != nil || values["run_time_hour"] != 23 || values["run_time_day"] != 31 {
		t.Fatal(values, err)
	}
}
