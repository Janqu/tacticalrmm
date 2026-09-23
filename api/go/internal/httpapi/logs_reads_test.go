package httpapi

import (
	"encoding/json"
	"testing"
)

func TestLogSortAndPage(t *testing.T) {
	if got, err := logSort(json.RawMessage(`"entry_time"`), true); err != nil || got != "l.entry_time DESC" {
		t.Fatal(got, err)
	}
	for _, raw := range []string{`"id;DROP TABLE x"`, `"debug_info__ip"`, `"-id"`, `null`} {
		if _, err := logSort(json.RawMessage(raw), false); err == nil {
			t.Fatal("unsafe sort accepted", raw)
		}
	}
	for _, test := range []struct {
		raw  string
		want int64
	}{{`2`, 2}, {`99`, 3}, {`0`, 3}, {`-1`, 3}, {`"bad"`, 1}, {`2.9`, 1}, {`null`, 1}} {
		if got := logPage(json.RawMessage(test.raw), 3); got != test.want {
			t.Errorf("%s: %d", test.raw, got)
		}
	}
}
