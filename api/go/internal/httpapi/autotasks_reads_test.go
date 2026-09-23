package httpapi

import (
	"encoding/json"
	"testing"
)

func TestAutoTaskSchedule(t *testing.T) {
	cases := []struct{ body, want string }{
		{`{"task_type":"daily","run_time_date":"2024-01-02T13:04:00Z","daily_interval":1}`, "Daily at 01:04PM"},
		{`{"task_type":"weekly","run_time_date":"2024-01-02T13:04:00Z","weekly_interval":1,"run_time_bit_weekdays":127}`, "Every day at 01:04PM every 1 weeks"},
		{`{"task_type":"weekly","run_time_date":"2024-01-02T13:04:00Z","weekly_interval":2,"run_time_bit_weekdays":2}`, "Monday at 01:04PM"},
		{`{"task_type":"monthly","run_time_date":"2024-01-02T13:04:00Z","monthly_months_of_year":4095,"monthly_days_of_month":2147483648}`, "Runs on Every month on days Last day at 01:04PM"},
		{`{"task_type":"monthlydow","run_time_date":"2024-01-02T13:04:00Z","monthly_months_of_year":3,"monthly_weeks_of_month":17,"run_time_bit_weekdays":10}`, "Runs on January, February on First Week, Last Week on Monday, Wednesday at 01:04PM"},
	}
	for _, tc := range cases {
		row, err := decodeRow(json.RawMessage(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		got, err := autoTaskSchedule(row)
		if err != nil || got != tc.want {
			t.Fatalf("%s: %v %v", tc.body, got, err)
		}
	}
	if _, err := autoTaskSchedule(map[string]any{"task_type": "daily"}); err == nil {
		t.Fatal("missing date accepted")
	}
}
