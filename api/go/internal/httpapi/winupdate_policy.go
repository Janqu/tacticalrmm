package httpapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"gorm.io/gorm"
)

// Nil context is a background/callback invocation: Django does not audit implicit
// policy creation without an explicitly established request username.
type patchPolicyAuditContext struct {
	Username  string
	DebugInfo map[string]any
}

func defaultWinUpdatePolicy() map[string]any {
	return map[string]any{"id": nil, "created_by": nil, "created_time": nil, "modified_by": nil, "modified_time": nil, "agent_id": nil, "policy_id": nil, "critical": "inherit", "important": "inherit", "moderate": "inherit", "low": "inherit", "other": "inherit", "run_time_hour": 3, "run_time_frequency": "inherit", "run_time_days": []any{}, "run_time_day": 1, "reboot_after_install": "inherit", "reprocess_failed_inherit": true, "reprocess_failed": false, "reprocess_failed_times": 5, "email_if_fail": false}
}

func mergeWinUpdatePolicy(agent, parent map[string]any) map[string]any {
	if parent == nil {
		return agent
	}
	result := map[string]any{}
	for key, value := range parent {
		result[key] = value
	}
	for _, key := range []string{"critical", "important", "moderate", "low", "other", "reboot_after_install"} {
		if agent[key] != "inherit" {
			result[key] = agent[key]
		}
	}
	if agent["run_time_frequency"] != "inherit" {
		for _, key := range []string{"run_time_frequency", "run_time_hour", "run_time_days"} {
			result[key] = agent[key]
		}
	}
	// run_time_day and reprocess_failed_inherit deliberately remain the parent values.
	if agent["reprocess_failed_inherit"] == false {
		for _, key := range []string{"reprocess_failed", "reprocess_failed_times", "email_if_fail"} {
			result[key] = agent[key]
		}
	}
	return result
}

// effectiveWinUpdatePolicy requires the caller's transaction. It resolves fresh
// policy state and may create the missing agent default, but never persists a merge.
func effectiveWinUpdatePolicy(tx *gorm.DB, agentID string, actor *patchPolicyAuditContext) (map[string]any, error) {
	var agent struct {
		ID       int64
		Hostname string
	}
	if err := tx.Raw("SELECT id,hostname FROM agents_agent WHERE agent_id = ? FOR UPDATE", agentID).Scan(&agent).Error; err != nil {
		return nil, err
	}
	if agent.ID == 0 {
		return nil, agentNotFound()
	}
	var ids []int64
	if err := tx.Table("winupdate_winupdatepolicy").Where("agent_id = ?", agent.ID).Order("id").Limit(1).Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	var own map[string]any
	if len(ids) > 0 {
		var err error
		own, err = readRow(tx, "winupdate_winupdatepolicy", ids[0], false)
		if err != nil {
			return nil, err
		}
	} else {
		own = defaultWinUpdatePolicy()
		own["agent_id"] = agent.ID
		if actor != nil && actor.Username != "" {
			debug := actor.DebugInfo
			if debug == nil {
				debug = map[string]any{}
			}
			if err := audit.Write(tx, audit.Entry{Username: actor.Username, Action: "add", ObjectType: "winupdatepolicy", Message: fmt.Sprintf("%s added winupdatepolicy %s", actor.Username, agent.Hostname), AfterValue: patchPolicyProjection(own), DebugInfo: debug}); err != nil {
				return nil, err
			}
			own["created_by"], own["modified_by"] = actor.Username, actor.Username
		}
		now := time.Now().UTC()
		own["created_time"], own["modified_time"] = now, now
		encoded, err := json.Marshal(own)
		if err != nil {
			return nil, err
		}
		columns := []string{"created_by", "created_time", "modified_by", "modified_time", "agent_id", "policy_id", "critical", "important", "moderate", "low", "other", "run_time_hour", "run_time_frequency", "run_time_days", "run_time_day", "reboot_after_install", "reprocess_failed_inherit", "reprocess_failed", "reprocess_failed_times", "email_if_fail"}
		names := strings.Join(columns, ",")
		var id int64
		if err := tx.Raw("INSERT INTO winupdate_winupdatepolicy ("+names+") SELECT "+names+" FROM jsonb_populate_record(NULL::winupdate_winupdatepolicy, ?::jsonb) RETURNING id", string(encoded)).Scan(&id).Error; err != nil {
			return nil, err
		}
		own, err = readRow(tx, "winupdate_winupdatepolicy", id, false)
		if err != nil {
			return nil, err
		}
	}
	context, err := resolveAgentPolicies(tx, agentID)
	if err != nil {
		return nil, err
	}
	for _, policy := range context.Policies {
		ids = nil
		if err := tx.Table("winupdate_winupdatepolicy").Where("policy_id = ?", policy.ID).Order("id").Limit(1).Pluck("id", &ids).Error; err != nil {
			return nil, err
		}
		if len(ids) > 0 {
			parent, err := readRow(tx, "winupdate_winupdatepolicy", ids[0], false)
			if err != nil {
				return nil, err
			}
			return mergeWinUpdatePolicy(own, parent), nil
		}
	}
	return own, nil
}

func approveAgentUpdates(tx *gorm.DB, agentID string, actor *patchPolicyAuditContext) (int64, error) {
	policy, err := effectiveWinUpdatePolicy(tx, agentID, actor)
	if err != nil {
		return 0, err
	}
	severities := []string{}
	for _, pair := range [][2]string{{"critical", "Critical"}, {"important", "Important"}, {"moderate", "Moderate"}, {"low", "Low"}, {"other", ""}} {
		if policy[pair[0]] == "approve" {
			severities = append(severities, pair[1])
		}
	}
	if len(severities) == 0 {
		return 0, nil
	}
	result := tx.Table("winupdate_winupdate").Where("agent_id = (SELECT id FROM agents_agent WHERE agent_id = ?) AND installed = false AND severity IN ? AND action <> 'approve'", agentID, severities).Update("action", "approve")
	return result.RowsAffected, result.Error
}

// No DISTINCT or NULL filtering: both duplicate GUIDs and nulls survive in source.
func approvedUpdateGUIDs(tx *gorm.DB, agentPK int64) ([]*string, error) {
	var rows []struct{ GUID *string }
	if err := tx.Table("winupdate_winupdate").Select("guid").Where("agent_id = ? AND action = 'approve' AND installed = false", agentPK).Find(&rows).Error; err != nil {
		return nil, err
	}
	guids := make([]*string, len(rows))
	for i, row := range rows {
		guids[i] = row.GUID
	}
	return guids, nil
}
