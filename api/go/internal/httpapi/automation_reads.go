package httpapi

import (
	"encoding/json"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerAutomationReads(app *fiber.App) {
	read := []string{fiber.MethodGet, fiber.MethodHead}
	base := "/automation/policies/"
	pk := ":pk<regex(^[0-9]+$)>/"
	app.Add(read, base, s.authenticate, automationReadPermission, s.automationPolicies)
	app.Add(read, base+"overview/", s.authenticate, automationReadPermission, s.automationOverview)
	app.Add(read, base+pk, s.authenticate, automationReadPermission, s.automationPolicies)
	app.Add(read, base+pk+"related/", s.authenticate, automationReadPermission, s.automationRelated)
}

func automationReadPermission(c fiber.Ctx) error {
	permission := "can_list_automation_policies"
	if c.Method() != fiber.MethodGet {
		permission = "can_manage_automation_policies"
	}
	if !principal(c).Can(permission) {
		return errForbidden()
	}
	return c.Next()
}

type AutomationPolicyRow struct {
	CreatedBy    *string `json:"created_by"`
	ModifiedBy   *string `json:"modified_by"`
	CreatedTime  *string `json:"created_time" gorm:"column:serialized_created_time"`
	ModifiedTime *string `json:"modified_time" gorm:"column:serialized_modified_time"`

	ID              int64           `json:"id"`
	Name            string          `json:"name"`
	Desc            *string         `json:"desc"`
	Active          bool            `json:"active"`
	Enforced        bool            `json:"enforced"`
	AlertTemplate   *int64          `json:"alert_template" gorm:"column:alert_template_id"`
	ExcludedSites   json.RawMessage `json:"excluded_sites"`
	ExcludedClients json.RawMessage `json:"excluded_clients"`
	ExcludedAgents  json.RawMessage `json:"excluded_agents"`
}

var automationPolicyFields = `p.*, ` + automationDate("p.created_time") + ` AS serialized_created_time, ` + automationDate("p.modified_time") + ` AS serialized_modified_time,
 COALESCE((SELECT jsonb_agg(e.site_id ORDER BY x.name) FROM automation_policy_excluded_sites e JOIN clients_site x ON x.id=e.site_id WHERE e.policy_id=p.id), '[]') AS excluded_sites,
 COALESCE((SELECT jsonb_agg(e.client_id ORDER BY x.name) FROM automation_policy_excluded_clients e JOIN clients_client x ON x.id=e.client_id WHERE e.policy_id=p.id), '[]') AS excluded_clients,
 COALESCE((SELECT jsonb_agg(e.agent_id ORDER BY e.id) FROM automation_policy_excluded_agents e WHERE e.policy_id=p.id), '[]') AS excluded_agents`

// Match Policy.related_agents, including its early return when both defaults
// refer to the policy and its explicit client/site inheritance rules.
const automationAgentCount = `(SELECT count(*) FROM agents_agent a
 JOIN clients_site t ON t.id=a.site_id JOIN clients_client cl ON cl.id=t.client_id
 WHERE NOT EXISTS (SELECT 1 FROM automation_policy_excluded_agents e WHERE e.policy_id=p.id AND e.agent_id=a.id)
 AND (
  (NOT a.block_policy_inheritance AND NOT t.block_policy_inheritance AND NOT cl.block_policy_inheritance
   AND NOT EXISTS (SELECT 1 FROM automation_policy_excluded_sites e WHERE e.policy_id=p.id AND e.site_id=t.id)
   AND NOT EXISTS (SELECT 1 FROM automation_policy_excluded_clients e WHERE e.policy_id=p.id AND e.client_id=cl.id)
   AND ((a.monitoring_type='server' AND EXISTS (SELECT 1 FROM core_coresettings cs WHERE cs.server_policy_id=p.id))
    OR (a.monitoring_type='workstation' AND EXISTS (SELECT 1 FROM core_coresettings cs WHERE cs.workstation_policy_id=p.id))))
  OR (
   NOT (EXISTS (SELECT 1 FROM core_coresettings cs WHERE cs.server_policy_id=p.id)
    AND EXISTS (SELECT 1 FROM core_coresettings cs WHERE cs.workstation_policy_id=p.id))
   AND NOT EXISTS (SELECT 1 FROM automation_policy_excluded_clients e WHERE e.policy_id=p.id AND e.client_id=cl.id)
   AND (
    (a.policy_id=p.id AND NOT EXISTS (SELECT 1 FROM automation_policy_excluded_sites e WHERE e.policy_id=p.id AND e.site_id=t.id))
    OR (NOT a.block_policy_inheritance AND NOT t.block_policy_inheritance AND (cl.server_policy_id=p.id OR cl.workstation_policy_id=p.id))
    OR (NOT a.block_policy_inheritance AND (t.server_policy_id=p.id OR t.workstation_policy_id=p.id)
     AND cl.server_policy_id IS DISTINCT FROM p.id AND cl.workstation_policy_id IS DISTINCT FROM p.id
     AND NOT EXISTS (SELECT 1 FROM automation_policy_excluded_sites e WHERE e.policy_id=p.id AND e.site_id=t.id))
   )
  )
 )) AS agents_count`

func automationDate(column string) string {
	return "CASE WHEN " + column + " IS NULL THEN NULL ELSE to_char(" + column + " AT TIME ZONE 'UTC', CASE WHEN extract(microseconds FROM " + column + ")::bigint % 1000000 = 0 THEN 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"' ELSE 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"' END) END"
}

func automationAuditJSON(alias string) string {
	return "jsonb_build_object('created_by'," + alias + ".created_by,'modified_by'," + alias + ".modified_by,'created_time'," + automationDate(alias+".created_time") + ",'modified_time'," + automationDate(alias+".modified_time") + ")"
}

type automationTableRow struct {
	AutomationPolicyRow `gorm:"embedded"`
	DefaultServer       bool            `json:"default_server_policy"`
	DefaultWorkstation  bool            `json:"default_workstation_policy"`
	AgentsCount         int64           `json:"agents_count"`
	WinUpdatePolicy     json.RawMessage `json:"winupdatepolicy"`
}

func (s *Server) automationPolicies(c fiber.Ctx) error {
	query := s.DB.WithContext(c.Context()).Table("automation_policy p")
	if c.Params("pk") != "" {
		id, err := identifier(c)
		if err != nil {
			return err
		}
		var rows []AutomationPolicyRow
		if err := query.Select(automationPolicyFields).Where("p.id = ?", id).Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return lookupError(gorm.ErrRecordNotFound, "Policy")
		}
		return c.JSON(rows[0])
	}
	rows := []automationTableRow{}
	fields := automationPolicyFields + `,
 EXISTS (SELECT 1 FROM core_coresettings cs WHERE cs.server_policy_id=p.id) AS default_server,
 EXISTS (SELECT 1 FROM core_coresettings cs WHERE cs.workstation_policy_id=p.id) AS default_workstation,
 COALESCE((SELECT jsonb_agg((` + automationAuditJSON("w") + ` || jsonb_build_object('id',w.id,'agent',w.agent_id,'policy',w.policy_id,'critical',w.critical,'important',w.important,'moderate',w.moderate,'low',w.low,'other',w.other,'run_time_hour',w.run_time_hour,'run_time_frequency',w.run_time_frequency,'run_time_days',w.run_time_days,'run_time_day',w.run_time_day,'reboot_after_install',w.reboot_after_install,'reprocess_failed_inherit',w.reprocess_failed_inherit,'reprocess_failed',w.reprocess_failed,'reprocess_failed_times',w.reprocess_failed_times,'email_if_fail',w.email_if_fail)) ORDER BY w.id) FROM winupdate_winupdatepolicy w WHERE w.policy_id=p.id), '[]') AS win_update_policy,` + automationAgentCount
	if err := query.Select(fields).Order("p.id").Find(&rows).Error; err != nil {
		return err
	}
	// ReadOnlyField(source="alert_template.id") is absent for a null template.
	out := make([]map[string]any, len(rows))
	for i, r := range rows {
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &out[i]); err != nil {
			return err
		}
		if r.AlertTemplate == nil {
			delete(out[i], "alert_template")
		}
	}
	return c.JSON(out)
}

func (s *Server) automationOverview(c fiber.Ctx) error {
	db := s.DB.WithContext(c.Context())
	policies := []AutomationPolicyRow{}
	if err := db.Table("automation_policy p").Select(automationPolicyFields).Find(&policies).Error; err != nil {
		return err
	}
	byID := map[int64]AutomationPolicyRow{}
	for _, p := range policies {
		byID[p.ID] = p
	}
	policy := func(id *int64) any {
		if id == nil {
			return nil
		}
		return byID[*id]
	}
	clients := []ClientSiteRow{}
	if err := clientSiteScope(db.Table("clients_client x"), c, true, false).Select("x.*").Order("x.name").Find(&clients).Error; err != nil {
		return err
	}
	ids := make([]int64, len(clients))
	for i, cl := range clients {
		ids[i] = cl.ID
	}
	sites := []siteReadRow{}
	// Django OverviewPolicy prefetches every site for visible clients.
	if len(ids) > 0 {
		if err := db.Table("clients_site").Where("client_id IN ?", ids).Order("name").Find(&sites).Error; err != nil {
			return err
		}
	}
	byClient := map[int64][]fiber.Map{}
	for _, site := range sites {
		byClient[site.Client] = append(byClient[site.Client], fiber.Map{"pk": site.ID, "name": site.Name, "workstation_policy": policy(site.WorkstationPolicy), "server_policy": policy(site.ServerPolicy)})
	}
	out := make([]fiber.Map, len(clients))
	for i, cl := range clients {
		entries := byClient[cl.ID]
		if entries == nil {
			entries = []fiber.Map{}
		}
		out[i] = fiber.Map{"pk": cl.ID, "name": cl.Name, "sites": entries, "workstation_policy": policy(cl.WorkstationPolicy), "server_policy": policy(cl.ServerPolicy)}
	}
	return c.JSON(out)
}

func (s *Server) automationRelated(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	db := s.DB.WithContext(c.Context())
	var rows []struct {
		ID                 int64
		Name               string
		DefaultServer      bool
		DefaultWorkstation bool
	}
	if err := db.Table("automation_policy p").Select(`p.id,p.name,
 EXISTS (SELECT 1 FROM core_coresettings cs WHERE cs.server_policy_id=p.id) AS default_server,
 EXISTS (SELECT 1 FROM core_coresettings cs WHERE cs.workstation_policy_id=p.id) AS default_workstation`).Where("p.id = ?", id).Find(&rows).Error; err != nil {
		return err
	}
	// DRF serializes the missing .first() instance as an unbound serializer.
	if len(rows) == 0 {
		return c.JSON(fiber.Map{"name": ""})
	}
	r := rows[0]
	out := fiber.Map{"pk": r.ID, "name": r.Name, "is_default_server_policy": r.DefaultServer, "is_default_workstation_policy": r.DefaultWorkstation}
	for _, kind := range []string{"workstation", "server"} {
		clients := []struct{ Payload json.RawMessage }{}
		fields := automationAuditJSON("x") + ` || jsonb_build_object('id',x.id,'name',x.name,'block_policy_inheritance',x.block_policy_inheritance,'failing_checks',x.failing_checks,'server_policy',x.server_policy_id,'workstation_policy',x.workstation_policy_id,'alert_template',x.alert_template_id) AS payload`
		if err := clientSiteScope(db.Table("clients_client x"), c, true, false).Where("x."+kind+"_policy_id = ?", id).Select(fields).Order("x.name").Find(&clients).Error; err != nil {
			return err
		}
		clientData := make([]json.RawMessage, len(clients))
		for i, r := range clients {
			clientData[i] = r.Payload
		}
		out[kind+"_clients"] = clientData
		sites := []struct{ Payload json.RawMessage }{}
		fields = automationAuditJSON("x") + ` || jsonb_build_object('id',x.id,'name',x.name,'block_policy_inheritance',x.block_policy_inheritance,'failing_checks',x.failing_checks,'server_policy',x.server_policy_id,'workstation_policy',x.workstation_policy_id,'alert_template',x.alert_template_id,'client',x.client_id,'client_name',parent.name) AS payload`
		if err := clientSiteScope(db.Table("clients_site x"), c, false, false).Joins("JOIN clients_client parent ON parent.id=x.client_id").Where("x."+kind+"_policy_id = ?", id).Select(fields).Order("x.name").Find(&sites).Error; err != nil {
			return err
		}
		siteData := make([]json.RawMessage, len(sites))
		for i, r := range sites {
			siteData[i] = r.Payload
		}
		out[kind+"_sites"] = siteData
	}
	agents := []struct{ Payload json.RawMessage }{}
	if err := agentScope(db.Table("agents_agent a").Joins("JOIN clients_site s ON s.id=a.site_id JOIN clients_client cl ON cl.id=s.client_id"), c).Where("a.policy_id = ?", id).Select(`jsonb_build_object('id',a.id,'hostname',a.hostname,'agent_id',a.agent_id,'site',s.name,'client',cl.name) AS payload`).Order("a.id").Find(&agents).Error; err != nil {
		return err
	}
	agentData := make([]json.RawMessage, len(agents))
	for i, r := range agents {
		agentData[i] = r.Payload
	}
	out["agents"] = agentData
	return c.JSON(out)
}
