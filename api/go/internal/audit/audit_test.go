package audit

import (
	"encoding/json"
	"testing"
)

func TestPythonJSONSize(t *testing.T) {
	cases := []struct {
		value   any
		encoded string
	}{
		{nil, "null"}, {true, "true"}, {false, "false"},
		{json.Number("123"), "123"},
		{"ä😀\n<", `"\u00e4\ud83d\ude00\n<"`},
		{map[string]any{"body": "\t"}, `{"body": "\t"}`},
		{[]any{"a", nil, false}, `["a", null, false]`},
	}
	for _, tc := range cases {
		if got := pythonJSONSize(tc.value); got != len(tc.encoded) {
			t.Errorf("size=%d want=%d", got, len(tc.encoded))
		}
	}
}
