package pep440

import "testing"

func TestVersionOrdering(t *testing.T) {
	ordered := []string{"1.0.dev0", "1a0.dev1", "1alpha0", "1a1", "1beta0", "1rc1", "1", "1+abc", "1+abc.1", "1+1", "1post0.dev0", "1.post0", "1post1", "1.1", "1!0", "999999999999999999999999999!0"}
	for i, raw := range ordered {
		a, err := Parse(raw)
		if err != nil {
			t.Fatal(raw, err)
		}
		for j, other := range ordered {
			b, err := Parse(other)
			if err != nil {
				t.Fatal(other, err)
			}
			want := 0
			if i < j {
				want = -1
			}
			if i > j {
				want = 1
			}
			if got := Compare(a, b); got != want {
				t.Errorf("%s versus %s = %d want %d", raw, other, got, want)
			}
		}
	}
	for _, pair := range [][2]string{{"v01.0.0", "0!1"}, {"1-01", "1.post1"}, {"1c0", "1preview"}, {"1+ABC-001", "1+abc.1"}} {
		a, err := Parse(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		b, err := Parse(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if Compare(a, b) != 0 {
			t.Fatal("unequal", pair)
		}
	}
	for _, raw := range []string{"", "invalid", "1.2foo", "1..2", "1rc١"} {
		if _, err := Parse(raw); err == nil {
			t.Fatal("accepted", raw)
		}
	}
}
