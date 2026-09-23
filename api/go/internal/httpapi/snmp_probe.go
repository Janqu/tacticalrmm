package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

// The readiness check compares the installed remote-agent payload to the
// source shipped with this release. The test detects changes to that source.
const snmpProbeSHA256 = "7bfad5cdedd3d0a68d22892426770fc3fb25c2928bae663415014adb9cf62add"

func snmpProbeScriptCurrent(body string) bool {
	digest := sha256.Sum256([]byte(body))
	return hex.EncodeToString(digest[:]) == snmpProbeSHA256
}

func snmpProbeArgsReady(actions json.RawMessage, siteID int64) bool {
	var entries []map[string]any
	if json.Unmarshal(actions, &entries) != nil || len(entries) != 1 {
		return false
	}
	args, ok := entries[0]["script_args"].([]any)
	if !ok {
		return false
	}
	key := fmt.Sprintf("{{global.snmp_api_key_%d}}", siteID)
	for _, arg := range args {
		if value, ok := arg.(string); ok && value == key {
			return true
		}
	}
	return false
}

func (s *Server) snmpSiteProbe(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	db := s.DB.WithContext(c.Context())
	if err := hasPermOnObject(db, c, true, id); err != nil {
		return err
	}
	var siteCount int64
	if err := db.Table("clients_site").Where("id = ?", id).Count(&siteCount).Error; err != nil {
		return err
	}
	if siteCount == 0 {
		return lookupError(gorm.ErrRecordNotFound, "Site")
	}
	agents := []agentListRow{}
	if err := db.Table("agents_agent").Select("id, hostname, monitoring_type, last_seen, offline_time, overdue_time").
		Where("site_id = ?", id).Order("hostname").Find(&agents).Error; err != nil {
		return err
	}
	now := time.Now()
	choices := []fiber.Map{}
	var candidate *agentListRow
	for i := range agents {
		agent := &agents[i]
		online := agentStatus(agent, now) == "online"
		choices = append(choices, fiber.Map{"id": agent.ID, "hostname": agent.Hostname, "online": online})
		if online && (candidate == nil || agent.MonitoringType < candidate.MonitoringType) {
			candidate = agent
		}
	}
	var task struct {
		ID      int64
		AgentID int64
		Enabled bool
		Actions json.RawMessage
	}
	if err := db.Table("autotasks_automatedtask t").Select("t.id, t.agent_id, t.enabled, t.actions").
		Joins("JOIN agents_agent a ON a.id = t.agent_id").Where("t.name = ? AND a.site_id = ?", "QDT SNMP Poller", id).
		Order("t.id").Limit(1).Find(&task).Error; err != nil {
		return err
	}
	var configured *agentListRow
	if task.ID != 0 {
		candidate = nil // A configured offline poller must not imply a working replacement.
		for i := range agents {
			if agents[i].ID == task.AgentID {
				configured = &agents[i]
				if agentStatus(configured, now) == "online" {
					candidate = configured
				}
				break
			}
		}
	}
	var script struct {
		ID         int64
		ScriptBody string
	}
	if err := db.Table("scripts_script").Select("id, script_body").Where("name = ? AND category = ?", "QDT SNMP Poller", "QDT").
		Order("id").Limit(1).Find(&script).Error; err != nil {
		return err
	}
	var key struct {
		ID    int64
		Ready bool
	}
	if err := db.Table("accounts_apikey k").Select(`k.id, ((k.expiration IS NULL OR k.expiration > ?) AND
		EXISTS (SELECT 1 FROM core_globalkvstore v WHERE v.name = ? AND v.value = k.key)) AS ready`, now, fmt.Sprintf("snmp_api_key_%d", id)).
		Joins("JOIN accounts_user u ON u.id = k.user_id").Where("k.name = ? AND u.is_active", fmt.Sprintf("snmp-probe-%d", id)).
		Order("k.id").Limit(1).Find(&key).Error; err != nil {
		return err
	}
	ready := script.ID != 0 && snmpProbeScriptCurrent(script.ScriptBody) && key.Ready && task.ID != 0 && task.Enabled &&
		configured != nil && agentStatus(configured, now) == "online" && snmpProbeArgsReady(task.Actions, id)
	out := fiber.Map{"agents": choices, "agent_id": nil, "script": script.ID != 0, "api_key": key.Ready,
		"needs_repair": !ready, "online_agent": nil, "task": nil}
	if candidate != nil {
		out["online_agent"] = candidate.Hostname
	}
	if task.ID != 0 && configured != nil {
		out["agent_id"] = task.AgentID
		out["task"] = fiber.Map{"enabled": task.Enabled, "agent": configured.Hostname}
	}
	return c.JSON(out)
}
