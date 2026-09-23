package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/amidaware/tacticalrmm/api/go/internal/database"
	"gorm.io/gorm"
)

func TestMergeWinUpdatePolicy(t *testing.T) {
	own := defaultWinUpdatePolicy()
	parent := defaultWinUpdatePolicy()
	own["critical"] = "manual"
	own["run_time_frequency"] = "monthly"
	own["run_time_hour"] = 14
	own["run_time_days"] = []any{1, 3}
	own["run_time_day"] = 25
	own["reprocess_failed_inherit"] = false
	own["reprocess_failed"] = true
	own["reprocess_failed_times"] = 8
	own["email_if_fail"] = true
	parent["critical"] = "approve"
	parent["run_time_day"] = 12
	parent["reprocess_failed_inherit"] = true
	result := mergeWinUpdatePolicy(own, parent)
	if result["critical"] != "manual" || result["run_time_hour"] != 14 || result["run_time_day"] != 12 || result["reprocess_failed_inherit"] != true || result["reprocess_failed_times"] != 8 || result["email_if_fail"] != true {
		t.Fatal(result)
	}
	if parent["critical"] != "approve" || parent["run_time_hour"] != 3 {
		t.Fatal("merged policy mutated source")
	}
	if mergeWinUpdatePolicy(own, nil)["run_time_day"] != 25 {
		t.Fatal("standalone policy changed")
	}
}

// Test bridge is opt-in and limited to an explicitly isolated local schema.
func TestWinUpdatePolicyContract(t *testing.T) {
	input := os.Getenv("TRMM_WINUPDATE_POLICY_INPUT")
	if input == "" {
		t.Skip("isolated contract bridge")
	}
	parsed, err := url.Parse(os.Getenv("TRMM_WINUPDATE_POLICY_DSN"))
	if err != nil || (parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1") {
		t.Fatal("local DB required")
	}
	db, err := database.Open(context.Background(), os.Getenv("TRMM_WINUPDATE_POLICY_DSN"))
	if err != nil {
		t.Fatal("connect isolated DB")
	}
	pool, _ := db.DB()
	defer pool.Close()
	var schema string
	if err := db.Raw("SELECT current_schema()").Scan(&schema).Error; err != nil || !strings.HasPrefix(schema, "go_contract_") {
		t.Fatal("isolated schema required")
	}
	var request struct {
		AgentID  string
		Actor    *patchPolicyAuditContext
		Approve  bool
		Rollback bool
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	output := map[string]any{}
	err = db.Transaction(func(tx *gorm.DB) error {
		policy, err := effectiveWinUpdatePolicy(tx, request.AgentID, request.Actor)
		if err != nil {
			return err
		}
		output["policy"] = patchPolicyProjection(policy)
		if request.Approve {
			changed, err := approveAgentUpdates(tx, request.AgentID, request.Actor)
			if err != nil {
				return err
			}
			output["changed"] = changed
		}
		var pk int64
		if err := tx.Table("agents_agent").Select("id").Where("agent_id = ?", request.AgentID).Scan(&pk).Error; err != nil {
			return err
		}
		guids, err := approvedUpdateGUIDs(tx, pk)
		if err != nil {
			return err
		}
		output["guids"] = guids
		if request.Rollback {
			return errors.New("contract rollback")
		}
		return nil
	})
	if err != nil {
		output = map[string]any{"error": true}
	}
	raw, err = json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("TRMM_WINUPDATE_POLICY_OUTPUT"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
