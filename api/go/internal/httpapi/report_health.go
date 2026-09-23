package httpapi

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func healthReportFilters(c fiber.Ctx) (fiber.Map, error) {
	filters := fiber.Map{"template": "health", "monitoring_type": "all", "patch_days": int64(30),
		"ram_below_gb": int64(8), "disk_free_below_percent": int64(10), "software_query": ""}
	problems := validationError{}
	for _, field := range []struct {
		name    string
		choices []string
	}{
		{"template", []string{"health", "inventory", "patches", "issues", "software", "low_ram", "low_disk", "reboots", "offline", "printers"}},
		{"monitoring_type", []string{"all", "server", "workstation"}},
	} {
		if value, present := lastQuery(c, field.name); present && value != "" {
			raw, _ := json.Marshal(value)
			parsed, messages := choiceField(raw, field.choices...)
			if len(messages) > 0 {
				problems[field.name] = messages
			} else {
				filters[field.name] = parsed
			}
		}
	}
	for _, field := range []struct {
		name string
		max  int64
	}{
		{"patch_days", 365}, {"ram_below_gb", 4096}, {"disk_free_below_percent", 100}, {"site_id", 2147483647},
	} {
		value, present := lastQuery(c, field.name)
		if !present {
			continue
		}
		// DRF's optional nullable field maps an empty HTML query value to null.
		if field.name == "site_id" && value == "" {
			filters[field.name] = nil
			continue
		}
		if value == "" {
			continue
		}
		raw, _ := json.Marshal(value)
		n, messages := positiveIntegerField(raw)
		if len(messages) == 0 && n < 1 {
			messages = []string{"Ensure this value is greater than or equal to 1."}
		}
		if len(messages) == 0 && n > field.max {
			messages = []string{fmt.Sprintf("Ensure this value is less than or equal to %d.", field.max)}
		}
		if len(messages) > 0 {
			problems[field.name] = messages
		} else {
			filters[field.name] = n
		}
	}
	if value, present := lastQuery(c, "software_query"); present {
		value = strings.TrimSpace(value)
		if utf8.RuneCountInString(value) > 120 {
			problems["software_query"] = []string{"Ensure this field has no more than 120 characters."}
		} else {
			filters["software_query"] = value
		}
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return filters, nil
}

type healthReportAgent struct {
	ID                                      int64
	AgentID, Hostname, MonitoringType, Site string
	SiteID                                  int64
	OperatingSystem                         *string
	LastSeen                                *time.Time
	NeedsReboot                             bool
	OfflineTime, OverdueTime                int64
}

func (s *Server) reportHealth(c fiber.Ctx) error {
	filters, err := healthReportFilters(c)
	if err != nil {
		return err
	}
	switch filters["template"] {
	case "health", "patches", "issues":
	default:
		return c.Status(501).JSON("Diese Berichtsvorlage ist in der Go-API noch nicht verfügbar.")
	}
	id, err := identifier(c)
	if err != nil {
		return err
	}
	var report fiber.Map
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var client reportSiteOption
		if err := tx.Table("clients_client").Select("id,name").Where("id = ?", id).Take(&client).Error; err != nil {
			return lookupError(err, "Client")
		}
		sites := []reportSiteOption{}
		if err := clientSiteScope(tx.Table("clients_site x"), c, false, false).Where("x.client_id = ?", id).
			Select("x.id,x.name").Order("x.id").Find(&sites).Error; err != nil {
			return err
		}
		if len(sites) == 0 {
			// Empty clients remain available to unrestricted roles and explicit
			// client grants, exactly like visible_sites in the Python reports.
			var allowed int64
			if err := clientSiteScope(tx.Table("clients_client x"), c, true, false).Where("x.id = ?", id).Count(&allowed).Error; err != nil {
				return err
			}
			if allowed == 0 {
				return errForbidden()
			}
		}
		if site, ok := filters["site_id"].(int64); ok {
			filtered := []reportSiteOption{}
			for _, row := range sites {
				if row.ID == site {
					filtered = append(filtered, row)
				}
			}
			if len(filtered) == 0 {
				return lookupError(gorm.ErrRecordNotFound, "Site")
			}
			sites = filtered
		}
		siteIDs := make([]int64, 0, len(sites))
		for _, site := range sites {
			siteIDs = append(siteIDs, site.ID)
		}
		query := tx.Table("agents_agent a").Joins("JOIN clients_site s ON s.id = a.site_id").Where("a.site_id IN ?", siteIDs)
		if filters["monitoring_type"] != "all" {
			query = query.Where("a.monitoring_type = ?", filters["monitoring_type"])
		}
		agents := []healthReportAgent{}
		if err := query.Select("a.id,a.agent_id,a.hostname,a.site_id,s.name AS site,a.monitoring_type,a.operating_system,a.last_seen,a.needs_reboot,a.offline_time,a.overdue_time").
			Order("a.hostname,a.id").Find(&agents).Error; err != nil {
			return err
		}
		var problem error
		report, problem = buildGoHealthReport(tx, client, sites, agents, filters, time.Now().UTC())
		return problem
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	return c.JSON(report)
}

func buildGoHealthReport(db *gorm.DB, client reportSiteOption, sites []reportSiteOption, agents []healthReportAgent, filters fiber.Map, now time.Time) (fiber.Map, error) {
	since := now.AddDate(0, 0, -int(filters["patch_days"].(int64)))
	summary := map[string]int64{}
	for _, key := range []string{"total_agents", "servers", "workstations", "online", "offline", "overdue", "patches_pending", "patches_installed_recently", "checks_failing", "open_alerts", "patches_missing", "needs_reboot"} {
		summary[key] = 0
	}
	agentRows := []fiber.Map{}
	alertRows := []fiber.Map{}
	ids := make([]int64, 0, len(agents))
	for _, agent := range agents {
		ids = append(ids, agent.ID)
	}
	counts := map[int64]int64{}
	if len(ids) > 0 {
		var totals []struct{ AgentID, Total int64 }
		if err := db.Table("alerts_alert").Where("agent_id IN ? AND NOT resolved", ids).Select("agent_id,count(*) AS total").Group("agent_id").Find(&totals).Error; err != nil {
			return nil, err
		}
		for _, row := range totals {
			counts[row.AgentID] = row.Total
			summary["open_alerts"] += row.Total
		}
		var rows []struct {
			ID                          int64
			AgentID, Hostname, Severity string
			Message                     *string
			AlertTime                   time.Time
		}
		if err := db.Table("alerts_alert al").Joins("JOIN agents_agent a ON a.id = al.agent_id").
			Where("al.agent_id IN ? AND NOT al.resolved", ids).Select("al.id,a.agent_id,a.hostname,al.severity,al.message,al.alert_time").
			Order("al.alert_time DESC,al.id").Limit(500).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, row := range rows {
			alertRows = append(alertRows, fiber.Map{"id": row.ID, "agent_id": row.AgentID, "hostname": row.Hostname, "severity": row.Severity, "message": row.Message, "alert_time": datetime(&row.AlertTime)})
		}
	}
	// ponytail: effective policy resolution is per-agent, like the source;
	// batch policy/patch queries if measured report sizes exceed this path.
	for _, agent := range agents {
		var patches struct{ Installed, InstalledRecently, Pending, Missing int64 }
		if err := db.Table("winupdate_winupdate").Where("agent_id = ?", agent.ID).
			Select("count(*) FILTER (WHERE installed) AS installed, count(*) FILTER (WHERE installed AND date_installed >= ?) AS installed_recently, count(*) FILTER (WHERE NOT installed AND action = 'approve') AS pending, count(*) FILTER (WHERE NOT installed AND action IN ('nothing','inherit')) AS missing", since).Find(&patches).Error; err != nil {
			return nil, err
		}
		checks, err := healthReportChecks(db, agent.AgentID)
		if err != nil {
			return nil, err
		}
		status := agentStatus(&agentListRow{LastSeen: agent.LastSeen, OfflineTime: agent.OfflineTime, OverdueTime: agent.OverdueTime}, now)
		summary["total_agents"]++
		summary[status]++
		if agent.MonitoringType == "server" {
			summary["servers"]++
		}
		if agent.MonitoringType == "workstation" {
			summary["workstations"]++
		}
		if agent.NeedsReboot {
			summary["needs_reboot"]++
		}
		summary["patches_pending"] += patches.Pending
		summary["patches_installed_recently"] += patches.InstalledRecently
		summary["patches_missing"] += patches.Missing
		summary["checks_failing"] += checks["failing"]
		agentRows = append(agentRows, fiber.Map{"agent_id": agent.AgentID, "site_id": agent.SiteID, "hostname": agent.Hostname, "site": agent.Site,
			"status": status, "monitoring_type": agent.MonitoringType, "operating_system": agent.OperatingSystem, "last_seen": datetime(agent.LastSeen), "needs_reboot": agent.NeedsReboot,
			"patches": fiber.Map{"installed": patches.Installed, "installed_recently": patches.InstalledRecently, "pending": patches.Pending, "missing": patches.Missing}, "checks": checks, "open_alerts": counts[agent.ID]})
	}
	return fiber.Map{"client": client, "generated_at": datetime(&now), "site_scope": sites, "patch_since": datetime(&since), "filters": filters,
		"alerts_truncated": summary["open_alerts"] > 500, "patch_lookback_days": filters["patch_days"], "summary": summary, "agents": agentRows, "alerts": alertRows}, nil
}

func healthReportChecks(db *gorm.DB, agentID string) (map[string]int64, error) {
	context, err := resolveAgentPolicies(db, agentID)
	if err != nil {
		return nil, err
	}
	policyIDs := []int64{}
	for _, p := range context.Policies {
		policyIDs = append(policyIDs, p.ID)
	}
	query := db.Table("checks_check ch").Joins("LEFT JOIN scripts_script sc ON sc.id=ch.script_id").Where("ch.agent_id = ?", context.ID)
	if len(policyIDs) > 0 {
		query = query.Or("ch.policy_id IN ?", policyIDs)
	}
	all := []inheritedCheck{}
	if err := query.Select("ch.id,ch.agent_id,ch.policy_id,ch.check_type,ch.disk,ch.ip,ch.svc_name,ch.script_id,ch.log_name,ch.event_id,to_jsonb(sc.supported_platforms) AS platforms").Order("ch.id").Find(&all).Error; err != nil {
		return nil, err
	}
	direct := []inheritedCheck{}
	byPolicy := map[int64][]inheritedCheck{}
	for _, ch := range all {
		if ch.Agent != nil && *ch.Agent == context.ID {
			direct = append(direct, ch)
		}
		if ch.Policy != nil {
			byPolicy[*ch.Policy] = append(byPolicy[*ch.Policy], ch)
		}
	}
	inherited, overridden, err := selectInheritedChecks(direct, byPolicy, context.Policies, context.Platform)
	if err != nil {
		return nil, err
	}
	excluded := map[int64]bool{}
	for _, id := range overridden {
		excluded[id] = true
	}
	ids := append([]int64{}, inherited...)
	for _, ch := range direct {
		if !excluded[ch.ID] {
			ids = append(ids, ch.ID)
		}
	}
	results := []struct {
		AssignedCheckID int64
		Status          string
	}{}
	if len(ids) > 0 {
		if err := db.Table("checks_checkresult").Select("assigned_check_id,status").Where("agent_id = ? AND assigned_check_id IN ?", context.ID, ids).Order("id").Find(&results).Error; err != nil {
			return nil, err
		}
	}
	statuses := map[int64]string{}
	for _, row := range results {
		if _, exists := statuses[row.AssignedCheckID]; !exists {
			statuses[row.AssignedCheckID] = row.Status
		}
	}
	summary := map[string]int64{"passing": 0, "failing": 0, "pending": 0}
	for _, id := range ids {
		status, exists := statuses[id]
		if !exists {
			status = "pending"
		}
		summary[status]++
	}
	return summary, nil
}
