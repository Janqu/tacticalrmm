package httpapi

import "testing"

func TestResetPatchPolicyFields(t *testing.T) {
	values := resetPatchValues()
	if len(values) != 8 || values["reprocess_failed_inherit"] != true {
		t.Fatalf("wrong reset fields: %v", values)
	}
	for _, field := range []string{"critical", "important", "moderate", "low", "other", "run_time_frequency", "reboot_after_install"} {
		if values[field] != "inherit" {
			t.Fatalf("%s not inherited", field)
		}
	}
	for _, field := range []string{"run_time_days", "run_time_hour", "run_time_day", "reprocess_failed", "reprocess_failed_times", "email_if_fail", "modified_by", "modified_time"} {
		if _, ok := values[field]; ok {
			t.Fatalf("preserved field %s would change", field)
		}
	}
}
