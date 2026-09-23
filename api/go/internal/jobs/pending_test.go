package jobs

import (
	"testing"
	"time"
)

func TestPEP440Equality(t *testing.T) {
	for _, pair := range [][2]string{
		{"v02.010.0", "2.10"}, {"00!2.10.0.0", "2.10"},
		{"2.10-alpha", "2.10a0"}, {"2.10beta_01", "2.10b1"},
		{"2.10c1", "2.10rc1"}, {"2.10pre01", "2.10preview1"},
		{"2.10rev", "2.10.post0"}, {"2.10r2", "2.10-02"},
		{"2.10dev", "2.10.dev0"}, {"2.10.post1-dev02", "2.10.post01.dev2"},
		{"2.10+ABC-001_xyz", "2.10.0+abc.1.xyz"}, {"001!2.010", "1!2.10.0"},
		{" 2.10rc01+LOCAL ", "2.10c1+local"},
	} {
		a, errA := canonicalVersion(pair[0])
		b, errB := canonicalVersion(pair[1])
		if errA != nil || errB != nil || a != b {
			t.Fatal(pair, a, b, errA, errB)
		}
	}
	for _, pair := range [][2]string{{"2.10", "2.10rc0"}, {"2.10", "2.10.post0"}, {"2.10", "2.10.dev0"}, {"2.10", "2.10+local"}, {"2.10+001", "2.10+001a"}, {"0!2.10", "1!2.10"}, {"2.10.0.1", "2.10"}} {
		a, _ := canonicalVersion(pair[0])
		b, _ := canonicalVersion(pair[1])
		if a == b {
			t.Fatal(pair)
		}
	}
	for _, raw := range []string{"", "unknown", "2..10", "2.10+", "2.10++x", "2.10evil", "٢.١٠", "2.10rc١", "1!", "-2.10"} {
		if _, err := canonicalVersion(raw); err == nil {
			t.Fatal("accepted", raw)
		}
	}
}

func TestPendingAgentOnline(t *testing.T) {
	now := time.Date(2025, 1, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		age              time.Duration
		offline, overdue int64
		want             bool
	}{
		{3 * time.Minute, 4, 30, true}, {4 * time.Minute, 4, 30, true}, {4*time.Minute + time.Microsecond, 4, 30, false},
		{30 * time.Minute, 4, 30, true}, {30*time.Minute - time.Microsecond, 4, 30, false}, {30*time.Minute + time.Microsecond, 4, 30, false},
		{-time.Hour, 4, 30, true}, {5 * time.Minute, 30, 4, true}, {30 * time.Minute, 30, 4, true}, {31 * time.Minute, 30, 4, false},
		{0, 0, 0, true}, {time.Microsecond, 0, 0, false},
	} {
		seen := now.Add(-tc.age)
		got, err := agentOnline(now, &seen, tc.offline, tc.overdue)
		if err != nil || got != tc.want {
			t.Fatal(tc, got, err)
		}
	}
	if got, err := agentOnline(now, nil, 4, 30); got || err != nil {
		t.Fatal(got, err)
	}
	if _, err := agentOnline(now, &now, 2147483647, 30); err == nil {
		t.Fatal("accepted Python datetime overflow")
	}
}
