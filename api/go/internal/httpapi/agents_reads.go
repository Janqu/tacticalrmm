package httpapi

import (
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

const forbidden = "You do not have permission to perform this action."

func errForbidden() error { return fiber.NewError(403, forbidden) }

func agentNotFound() error { return fiber.NewError(404, "No Agent matches the given query.") }

// registerAgentReads wires agent reads and note writes from agents/urls.py. Literal
// routes come first: Django's <agent:agent_id> converter needs 21+ characters,
// which agentID enforces for the parameterised routes.
func (s *Server) registerAgentReads(app *fiber.App) {
	read := []string{fiber.MethodGet, fiber.MethodHead}
	pk := ":pk<regex(^[0-9]+$)>"
	app.Add(read, "/agents/", s.authenticate, s.agentList)
	app.Add(read, "/agents/v2/history/", s.authenticate, s.agentHistory(true))
	app.Add(read, "/agents/v2/:agent_id/history/", s.authenticate, s.agentHistory(true))
	app.Add(read, "/agents/history/", s.authenticate, s.agentHistory(false))
	app.Add(read, "/agents/notes/", s.authenticate, s.agentNotes)
	app.Add(read, "/agents/notes/"+pk+"/", s.authenticate, s.agentNote)
	app.Post("/agents/notes/", s.authenticate, s.addAgentNote)
	app.Add([]string{fiber.MethodPut, fiber.MethodDelete}, "/agents/notes/"+pk+"/", s.authenticate, s.writeAgentNote)
	app.Add(read, "/agents/:agent_id/history/", s.authenticate, s.agentHistory(false))
	app.Add(read, "/agents/:agent_id/notes/", s.authenticate, s.agentNotes)
}

func agentID(c fiber.Ctx) (string, error) {
	id := c.Params("agent_id")
	if id != "" && utf8.RuneCountInString(id) < 21 {
		return "", fiber.NewError(404, "Not found.")
	}
	return id, nil
}

// agentScope is PermissionQuerySet.filter_by_role for rows joined as a (agent)
// and s (site); it does not check the role's permission flags.
func agentScope(db *gorm.DB, c fiber.Ctx) *gorm.DB {
	p := principal(c)
	if p.User.IsSuperuser || (p.Role != nil && p.Role.IsSuperuser) {
		return db
	}
	if p.Role == nil {
		return db.Where("FALSE")
	}
	clients := "SELECT client_id FROM accounts_role_can_view_clients WHERE role_id = ?"
	sites := "SELECT site_id FROM accounts_role_can_view_sites WHERE role_id = ?"
	return db.Where("(NOT EXISTS ("+clients+") AND NOT EXISTS ("+sites+")) OR s.client_id IN ("+clients+") OR a.site_id IN ("+sites+")",
		p.Role.ID, p.Role.ID, p.Role.ID, p.Role.ID)
}

// hasPermOnAgent is tacticalrmm.permissions._has_perm_on_agent, including its
// 404 for unknown agents once the user is neither superuser nor role-less.
func (s *Server) hasPermOnAgent(c fiber.Ctx, id string) error {
	p := principal(c)
	if p.User.IsInstallerUser {
		return errForbidden()
	}
	if p.User.IsSuperuser || (p.Role != nil && p.Role.IsSuperuser) {
		return nil
	}
	if p.Role == nil {
		return errForbidden()
	}
	db := s.DB.WithContext(c.Context())
	base := func() *gorm.DB {
		return db.Table("agents_agent a").Joins("JOIN clients_site s ON s.id = a.site_id").Where("a.agent_id = ?", id)
	}
	var exists int64
	if err := base().Count(&exists).Error; err != nil {
		return err
	}
	if exists == 0 {
		return agentNotFound()
	}
	var allowed int64
	if err := agentScope(base(), c).Count(&allowed).Error; err != nil {
		return err
	}
	if allowed == 0 {
		return errForbidden()
	}
	return nil
}

// agentPK is get_object_or_404(Agent, agent_id=...).
func (s *Server) agentPK(c fiber.Ctx, id string) (int64, error) {
	var pk int64
	res := s.DB.WithContext(c.Context()).Table("agents_agent").Select("id").Where("agent_id = ?", id).Limit(1).Scan(&pk)
	if res.Error != nil {
		return 0, res.Error
	}
	if res.RowsAffected == 0 {
		return 0, agentNotFound()
	}
	return pk, nil
}

func lastQuery(c fiber.Ctx, key string) (string, bool) {
	values := c.RequestCtx().QueryArgs().PeekMulti(key)
	if len(values) == 0 {
		return "", false
	}
	return string(values[len(values)-1]), true
}

type agentListRow struct {
	ID                    int64           `gorm:"column:id"`
	AgentID               string          `gorm:"column:agent_id"`
	Hostname              string          `gorm:"column:hostname"`
	MonitoringType        string          `gorm:"column:monitoring_type"`
	Description           *string         `gorm:"column:description"`
	NeedsReboot           bool            `gorm:"column:needs_reboot"`
	OverdueTextAlert      bool            `gorm:"column:overdue_text_alert"`
	OverdueEmailAlert     bool            `gorm:"column:overdue_email_alert"`
	OverdueDashboardAlert bool            `gorm:"column:overdue_dashboard_alert"`
	LastSeen              *time.Time      `gorm:"column:last_seen"`
	BootTime              *float64        `gorm:"column:boot_time"`
	MaintenanceMode       bool            `gorm:"column:maintenance_mode"`
	LoggedInUsername      *string         `gorm:"column:logged_in_username"`
	LastLoggedInUser      *string         `gorm:"column:last_logged_in_user"`
	PolicyID              *int64          `gorm:"column:policy_id"`
	BlockInheritance      bool            `gorm:"column:block_policy_inheritance"`
	Plat                  string          `gorm:"column:plat"`
	Goarch                *string         `gorm:"column:goarch"`
	Version               string          `gorm:"column:version"`
	OperatingSystem       *string         `gorm:"column:operating_system"`
	PublicIP              *string         `gorm:"column:public_ip"`
	WMIDetail             json.RawMessage `gorm:"column:wmi_detail"`
	OfflineTime           int64           `gorm:"column:offline_time"`
	OverdueTime           int64           `gorm:"column:overdue_time"`
	SiteName              string          `gorm:"column:site_name"`
	ClientName            string          `gorm:"column:client_name"`
	AlertTemplateID       *int64          `gorm:"column:alert_template_id"`
	TemplateName          *string         `gorm:"column:template_name"`
	TemplateEmail         *bool           `gorm:"column:template_email"`
	TemplateText          *bool           `gorm:"column:template_text"`
	TemplateAlert         *bool           `gorm:"column:template_alert"`
	HasPatchesPending     bool            `gorm:"column:has_patches_pending"`
	PendingActions        int64           `gorm:"column:pending_actions_count"`
	MatrixNames           json.RawMessage `gorm:"column:matrix_names"`
	CustomFields          json.RawMessage `gorm:"column:custom_fields"`
}

const agentListSelect = `a.id, a.agent_id, a.hostname, a.monitoring_type, a.description, a.needs_reboot,
	a.overdue_text_alert, a.overdue_email_alert, a.overdue_dashboard_alert, a.last_seen, a.boot_time,
	a.maintenance_mode, a.logged_in_username, a.last_logged_in_user, a.policy_id, a.block_policy_inheritance,
	a.plat, a.goarch, a.version, a.operating_system, a.public_ip, a.wmi_detail, a.offline_time, a.overdue_time,
	s.name AS site_name, c.name AS client_name, a.alert_template_id, t.name AS template_name,
	t.agent_always_email AS template_email, t.agent_always_text AS template_text, t.agent_always_alert AS template_alert,
	EXISTS (SELECT 1 FROM winupdate_winupdate w WHERE w.agent_id = a.id AND w.action = 'approve' AND NOT w.installed) AS has_patches_pending,
	(SELECT count(*) FROM logs_pendingaction pa WHERE pa.agent_id = a.id AND pa.status = 'pending') AS pending_actions_count,
	COALESCE((SELECT jsonb_agg(DISTINCT m.name) FROM alerts_matrixchannel m WHERE m.enabled AND (
		m.id IN (SELECT matrixchannel_id FROM agents_agent_matrix_channels WHERE agent_id = a.id)
		OR m.id IN (SELECT matrixchannel_id FROM alerts_alerttemplate_matrix_channels WHERE alerttemplate_id = a.alert_template_id))
	), '[]'::jsonb) AS matrix_names,
	COALESCE((SELECT jsonb_agg(jsonb_build_object('id', v.id, 'field', v.field_id, 'agent', v.agent_id,
		'value', CASE f.type WHEN 'multiple' THEN to_jsonb(v.multiple_value) WHEN 'checkbox' THEN to_jsonb(v.bool_value)
			ELSE to_jsonb(v.string_value) END) ORDER BY v.id)
		FROM agents_agentcustomfield v JOIN core_customfield f ON f.id = v.field_id WHERE v.agent_id = a.id), '[]'::jsonb) AS custom_fields`

// GET /agents/. Django's AgentPerms sends HEAD down the edit branch, which
// reads a missing agent_id kwarg and crashes; keep the 403/500 outcomes.
func (s *Server) agentList(c fiber.Ctx) error {
	p := principal(c)
	if c.Method() == fiber.MethodHead {
		if !p.Can("can_edit_agent") {
			return errForbidden()
		}
		return errors.New("HEAD /agents/ raises KeyError in Django")
	}
	if !p.Can("can_list_agents") {
		return errForbidden()
	}
	db := s.DB.WithContext(c.Context())
	query := agentScope(db.Table("agents_agent a").
		Joins("JOIN clients_site s ON s.id = a.site_id JOIN clients_client c ON c.id = s.client_id").
		Joins("LEFT JOIN alerts_alerttemplate t ON t.id = a.alert_template_id"), c)
	if mt, _ := lastQuery(c, "monitoring_type"); mt != "" {
		if mt != "server" && mt != "workstation" {
			return c.Status(400).JSON("monitoring type does not exist")
		}
		query = query.Where("a.monitoring_type = ?", mt)
	}
	for _, f := range []struct{ key, column string }{{"site", "a.site_id"}, {"client", "s.client_id"}} {
		if raw, ok := lastQuery(c, f.key); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
			if err != nil {
				// Django raises ValueError for a non-integer id filter.
				return errors.New("invalid " + f.key + " filter")
			}
			query = query.Where(f.column+" = ?", n)
			break
		}
	}
	detail := "true"
	if v, ok := lastQuery(c, "detail"); ok {
		detail = v
	}
	if detail != "true" {
		var rows []struct {
			ID       int64  `gorm:"column:id"`
			Hostname string `gorm:"column:hostname"`
			AgentID  string `gorm:"column:agent_id"`
			Client   string `gorm:"column:client"`
			Site     string `gorm:"column:site"`
		}
		if err := query.Select("a.id, a.hostname, a.agent_id, c.name AS client, s.name AS site").Order("a.id").Find(&rows).Error; err != nil {
			return err
		}
		out := make([]fiber.Map, len(rows))
		for i, r := range rows {
			out[i] = fiber.Map{"id": r.ID, "hostname": r.Hostname, "agent_id": r.AgentID, "client": r.Client, "site": r.Site}
		}
		return c.JSON(out)
	}
	var rows []agentListRow
	if err := query.Select(agentListSelect).Order("a.id").Find(&rows).Error; err != nil {
		return err
	}
	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	checks, err := s.agentChecks(c.Context(), ids)
	if err != nil {
		return err
	}
	now := time.Now()
	out := make([]fiber.Map, len(rows))
	for i := range rows {
		out[i] = agentTableEntry(&rows[i], checks[rows[i].ID], now)
	}
	return c.JSON(out)
}

func agentStatus(r *agentListRow, now time.Time) string {
	if r.LastSeen == nil {
		return "offline"
	}
	offline := now.Add(-time.Duration(r.OfflineTime) * time.Minute)
	overdue := now.Add(-time.Duration(r.OverdueTime) * time.Minute)
	switch {
	case r.LastSeen.Before(offline) && r.LastSeen.After(overdue):
		return "offline"
	case r.LastSeen.Before(offline) && r.LastSeen.Before(overdue):
		return "overdue"
	}
	return "online"
}

func agentTableEntry(r *agentListRow, checks map[string]any, now time.Time) fiber.Map {
	status := agentStatus(r, now)
	wmi := decodeWMI(r.WMIDetail)
	var names []string
	_ = json.Unmarshal(r.MatrixNames, &names)
	sort.Strings(names)
	if names == nil {
		names = []string{}
	}
	var template any
	if r.AlertTemplateID != nil {
		template = fiber.Map{"name": r.TemplateName, "always_email": r.TemplateEmail, "always_text": r.TemplateText, "always_alert": r.TemplateAlert}
	}
	// logged_username / italic mirror AgentTableSerializer, including None.
	var logged any = "-"
	italic := false
	switch {
	case r.LoggedInUsername != nil && *r.LoggedInUsername == "None":
		italic = status == "online"
		if italic {
			logged = r.LastLoggedInUser
		}
	default:
		logged = r.LoggedInUsername
	}
	entry := fiber.Map{
		"agent_id": r.AgentID, "alert_template": template, "hostname": r.Hostname,
		"site_name": r.SiteName, "client_name": r.ClientName, "monitoring_type": r.MonitoringType,
		"description": r.Description, "needs_reboot": r.NeedsReboot, "pending_actions_count": r.PendingActions,
		"status": status, "overdue_text_alert": r.OverdueTextAlert, "overdue_email_alert": r.OverdueEmailAlert,
		"overdue_dashboard_alert": r.OverdueDashboardAlert, "matrix_channels": names,
		"last_seen": datetime(r.LastSeen), "boot_time": r.BootTime, "checks": checks,
		"maintenance_mode": r.MaintenanceMode, "logged_username": logged, "italic": italic,
		"block_policy_inheritance": r.BlockInheritance, "plat": r.Plat, "goarch": r.Goarch,
		"has_patches_pending": r.HasPatchesPending, "version": r.Version, "operating_system": r.OperatingSystem,
		"public_ip": r.PublicIP, "cpu_model": cpuModel(r.Plat, wmi), "graphics": graphics(r.Plat, wmi),
		"local_ips": localIPs(r.Plat, wmi), "make_model": makeModel(r.Plat, wmi),
		"physical_disks": physicalDisks(r.Plat, wmi), "custom_fields": r.CustomFields,
		"serial_number": serialNumber(r.Plat, wmi),
	}
	if r.PolicyID != nil { // ReadOnlyField(source="policy.id") is skipped for a null policy
		entry["policy"] = *r.PolicyID
	}
	return entry
}

type noteRow struct {
	PK        int64      `gorm:"column:pk"`
	EntryTime *time.Time `gorm:"column:entry_time"`
	Note      *string    `gorm:"column:note"`
	Username  *string    `gorm:"column:username"`
	AgentID   string     `gorm:"column:agent_id"`
}

const noteSelect = "n.id AS pk, n.entry_time, n.note, u.username, a.agent_id"

func noteEntry(r noteRow) fiber.Map {
	entry := fiber.Map{"pk": r.PK, "entry_time": datetime(r.EntryTime), "note": r.Note, "agent_id": r.AgentID}
	if r.Username != nil {
		entry["username"] = *r.Username
	}
	return entry
}

func (s *Server) notesQuery(c fiber.Ctx) *gorm.DB {
	return s.DB.WithContext(c.Context()).Table("agents_note n").
		Joins("JOIN agents_agent a ON a.id = n.agent_id JOIN clients_site s ON s.id = a.site_id").
		Joins("LEFT JOIN accounts_user u ON u.id = n.user_id").Select(noteSelect)
}

// AgentNotesPerms: HEAD is checked as a management request without agent scope.
func notesPerm(c fiber.Ctx) error {
	perm := "can_list_notes"
	if c.Method() != fiber.MethodGet {
		perm = "can_manage_notes"
	}
	if !principal(c).Can(perm) {
		return errForbidden()
	}
	return nil
}

func (s *Server) agentNotes(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	if err := notesPerm(c); err != nil {
		return err
	}
	query := s.notesQuery(c)
	if id != "" {
		if c.Method() == fiber.MethodGet {
			if err := s.hasPermOnAgent(c, id); err != nil {
				return err
			}
		}
		pk, err := s.agentPK(c, id)
		if err != nil {
			return err
		}
		query = query.Where("n.agent_id = ?", pk)
	} else {
		query = agentScope(query, c)
	}
	rows := []noteRow{}
	if err := query.Order("n.id").Find(&rows).Error; err != nil {
		return err
	}
	out := make([]fiber.Map, len(rows))
	for i, r := range rows {
		out[i] = noteEntry(r)
	}
	return c.JSON(out)
}

func (s *Server) agentNote(c fiber.Ctx) error {
	if err := notesPerm(c); err != nil {
		return err
	}
	pk, err := identifier(c)
	if err != nil {
		return err
	}
	var rows []noteRow
	if err := s.notesQuery(c).Where("n.id = ?", pk).Find(&rows).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		return fiber.NewError(404, "No Note matches the given query.")
	}
	if err := s.hasPermOnAgent(c, rows[0].AgentID); err != nil {
		return err
	}
	return c.JSON(noteEntry(rows[0]))
}

type historyRow struct {
	ID              int64           `gorm:"column:id"`
	Agent           int64           `gorm:"column:agent_id"`
	Time            *time.Time      `gorm:"column:time"`
	Type            string          `gorm:"column:type"`
	Command         *string         `gorm:"column:command"`
	Username        string          `gorm:"column:username"`
	Results         *string         `gorm:"column:results"`
	Script          *int64          `gorm:"column:script_id"`
	ScriptResults   json.RawMessage `gorm:"column:script_results"`
	CustomField     *int64          `gorm:"column:custom_field_id"`
	CollectorAll    bool            `gorm:"column:collector_all_output"`
	SaveToAgentNote bool            `gorm:"column:save_to_agent_note"`
	ScriptName      *string         `gorm:"column:script_name"`
}

func historyEntry(r historyRow) fiber.Map {
	entry := fiber.Map{
		"id": r.ID, "agent": r.Agent, "time": datetime(r.Time), "type": r.Type, "command": r.Command,
		"username": r.Username, "results": r.Results, "script": r.Script, "script_results": r.ScriptResults,
		"custom_field": r.CustomField, "collector_all_output": r.CollectorAll, "save_to_agent_note": r.SaveToAgentNote,
	}
	if r.ScriptName != nil {
		entry["script_name"] = *r.ScriptName
	}
	return entry
}

// AgentHistoryView (v1, unpaginated, unordered -> id order) and
// AgentHistoryViewV2 (ordering + StandardPagination).
func (s *Server) agentHistory(v2 bool) fiber.Handler {
	return func(c fiber.Ctx) error {
		id, err := agentID(c)
		if err != nil {
			return err
		}
		if !principal(c).Can("can_list_agent_history") {
			return errForbidden()
		}
		query := s.DB.WithContext(c.Context()).Table("agents_agenthistory h").
			Joins("JOIN agents_agent a ON a.id = h.agent_id JOIN clients_site s ON s.id = a.site_id").
			Joins("LEFT JOIN scripts_script sc ON sc.id = h.script_id")
		if id != "" {
			if err := s.hasPermOnAgent(c, id); err != nil {
				return err
			}
			pk, err := s.agentPK(c, id)
			if err != nil {
				return err
			}
			query = query.Where("h.agent_id = ?", pk)
		} else {
			query = agentScope(query, c)
		}
		const columns = "h.id, h.agent_id, h.time, h.type, h.command, h.username, h.results, h.script_id, h.script_results, h.custom_field_id, h.collector_all_output, h.save_to_agent_note, sc.name AS script_name"
		rows := []historyRow{}
		if !v2 {
			if err := query.Select(columns).Order("h.id").Find(&rows).Error; err != nil {
				return err
			}
			return c.JSON(historyEntries(rows))
		}
		order, err := historyOrder(c)
		if err != nil {
			return err
		}
		var count int64
		if err := query.Count(&count).Error; err != nil {
			return err
		}
		size := pageSize(c)
		pages := (count + size - 1) / size
		if pages < 1 {
			pages = 1
		}
		page, err := pageNumber(c, pages)
		if err != nil {
			return err
		}
		if err := query.Select(columns).Order(order).Limit(int(size)).Offset(int((page - 1) * size)).Find(&rows).Error; err != nil {
			return err
		}
		var next, previous any
		if page < pages {
			next = pageLink(c, page+1)
		}
		if page > 1 {
			previous = pageLink(c, page-1)
		}
		return c.JSON(fiber.Map{"count": count, "next": next, "previous": previous, "results": historyEntries(rows)})
	}
}

func historyEntries(rows []historyRow) []fiber.Map {
	out := make([]fiber.Map, len(rows))
	for i, r := range rows {
		out[i] = historyEntry(r)
	}
	return out
}

func historyOrder(c fiber.Ctx) (string, error) {
	ordering, ok := lastQuery(c, "ordering")
	if !ok {
		ordering = "-time"
	}
	name := strings.TrimLeft(ordering, "-")
	switch name {
	case "time", "type", "command", "username":
	default:
		return "h.time DESC, h.id DESC", nil
	}
	switch ordering {
	case name:
		return "h." + name + ", h.id DESC", nil
	case "-" + name:
		return "h." + name + " DESC, h.id DESC", nil
	}
	return "", errors.New("invalid order_by arguments") // Django raises FieldError
}

func pageSize(c fiber.Ctx) int64 {
	raw, ok := lastQuery(c, "page_size")
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if !ok || err != nil || n <= 0 {
		return 100
	}
	return min(n, 1000)
}

func pageNumber(c fiber.Ctx, pages int64) (int64, error) {
	raw, ok := lastQuery(c, "page")
	if !ok {
		return 1, nil
	}
	if raw == "last" {
		return pages, nil
	}
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || n < 1 || n > pages {
		return 0, fiber.NewError(404, "Invalid page.")
	}
	return n, nil
}

// pageLink follows DRF's replace_query_param/remove_query_param: sorted keys,
// and page=1 is dropped from the URL.
func pageLink(c fiber.Ctx, page int64) string {
	query, _ := url.ParseQuery(string(c.RequestCtx().URI().QueryString()))
	if page == 1 {
		query.Del("page")
	} else {
		query.Set("page", strconv.FormatInt(page, 10))
	}
	link := c.Scheme() + "://" + c.Host() + c.Path()
	if encoded := query.Encode(); encoded != "" {
		link += "?" + encoded
	}
	return link
}
