package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

// notifyError reproduces Django's notify_error(): a 400 whose body is a JSON string.
type notifyError string

func (e notifyError) Error() string { return string(e) }

const forbiddenMessage = "You do not have permission to perform this action."

func writeError(c fiber.Ctx, err error) error {
	var ne notifyError
	if errors.As(err, &ne) {
		return c.Status(400).JSON(string(ne))
	}
	return err
}

// orgRecord is a clients_client or clients_site row (ClientID is site-only).
type orgRecord struct {
	ID                     int64
	CreatedBy              *string
	CreatedTime            *time.Time
	ModifiedBy             *string
	ModifiedTime           *time.Time
	ClientID               int64
	Name                   string
	BlockPolicyInheritance bool
	FailingChecks          json.RawMessage
	WorkstationPolicyID    *int64
	ServerPolicyID         *int64
	AlertTemplateID        *int64
}

// audit mirrors ClientAuditSerializer / SiteAuditSerializer (fields = "__all__").
func (r orgRecord) audit(site bool) map[string]any {
	v := map[string]any{"id": nil, "created_by": r.CreatedBy, "created_time": datetime(r.CreatedTime),
		"modified_by": r.ModifiedBy, "modified_time": datetime(r.ModifiedTime), "name": r.Name,
		"block_policy_inheritance": r.BlockPolicyInheritance, "failing_checks": json.RawMessage(r.FailingChecks),
		"workstation_policy": r.WorkstationPolicyID, "server_policy": r.ServerPolicyID, "alert_template": r.AlertTemplateID}
	if r.ID != 0 {
		v["id"] = r.ID
	}
	if site {
		v["client"] = r.ClientID
	}
	return v
}

func orgTable(site bool) string {
	if site {
		return "clients_site"
	}
	return "clients_client"
}

func objectType(site bool) string {
	if site {
		return "site"
	}
	return "client"
}

func loadOrg(tx *gorm.DB, site bool, id int64, lock bool) (orgRecord, error) {
	q := "SELECT * FROM " + orgTable(site) + " WHERE id = ?"
	if lock {
		q += " FOR UPDATE"
	}
	var rows []orgRecord
	if err := tx.Raw(q, id).Scan(&rows).Error; err != nil {
		return orgRecord{}, err
	}
	if len(rows) == 0 {
		return orgRecord{}, lookupError(gorm.ErrRecordNotFound, strings.ToUpper(objectType(site)[:1])+objectType(site)[1:])
	}
	return rows[0], nil
}

// hasPermOnObject follows tacticalrmm.permissions._has_perm_on_client/_site,
// including the 404 for missing objects that non-superuser role holders see.
func hasPermOnObject(db *gorm.DB, c fiber.Ctx, site bool, id int64) error {
	p := principal(c)
	if p.User.IsSuperuser || (p.Role != nil && p.Role.IsSuperuser) {
		return nil
	}
	if p.Role == nil {
		return fiber.NewError(403, forbiddenMessage)
	}
	rec, err := loadOrg(db, site, id, false)
	if err != nil {
		return err
	}
	var clients, sites, inClient, inSite int64
	role := p.Role.ID
	for _, q := range []struct {
		out  *int64
		sql  string
		args []any
	}{
		{&clients, "SELECT count(*) FROM accounts_role_can_view_clients WHERE role_id = ?", []any{role}},
		{&sites, "SELECT count(*) FROM accounts_role_can_view_sites WHERE role_id = ?", []any{role}},
		{&inSite, "SELECT count(*) FROM accounts_role_can_view_sites WHERE role_id = ? AND site_id = ?", []any{role, id}},
		{&inClient, "SELECT count(*) FROM accounts_role_can_view_clients WHERE role_id = ? AND client_id = ?", []any{role, map[bool]int64{false: id, true: rec.ClientID}[site]}},
	} {
		if err := db.Raw(q.sql, q.args...).Scan(q.out).Error; err != nil {
			return err
		}
	}
	switch {
	case !site && (clients == 0 || inClient > 0):
		return nil
	case site && ((clients == 0 && sites == 0) || inSite > 0 || inClient > 0):
		return nil
	}
	return fiber.NewError(403, forbiddenMessage)
}

func (s *Server) requireOnObject(site bool) fiber.Handler {
	return func(c fiber.Ctx) error {
		id, err := identifier(c)
		if err != nil {
			return err
		}
		if err := hasPermOnObject(s.DB.WithContext(c.Context()), c, site, id); err != nil {
			return err
		}
		return c.Next()
	}
}

func (s *Server) registerClientSiteWrites(app *fiber.App) {
	app.Post("/clients/", s.authenticate, require("can_manage_clients"), s.addClient)
	app.Put("/clients/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_manage_clients"), s.requireOnObject(false), s.updateClient)
	app.Delete("/clients/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_manage_clients"), s.requireOnObject(false), s.deleteClient)
	app.Post("/clients/sites/", s.authenticate, require("can_manage_sites"), s.addSite)
	app.Put("/clients/sites/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_manage_sites"), s.requireOnObject(true), s.updateSite)
	app.Delete("/clients/sites/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_manage_sites"), s.requireOnObject(true), s.deleteSite)
	s.registerCustomFields(app)
}

func debugInfo(c fiber.Ctx, view string, kwargs map[string]any) map[string]any {
	return map[string]any{"url": c.Path(), "method": c.Method(), "view_class": view, "view_func": view,
		"view_args": []any{}, "view_kwargs": kwargs, "ip": c.IP()}
}

// subObject extracts request.data[key], which Django indexes without checking.
func subObject(input map[string]json.RawMessage, key string) (map[string]json.RawMessage, error) {
	raw, ok := input[key]
	if !ok {
		return nil, validationError{key: {"This field is required."}}
	}
	var obj map[string]json.RawMessage
	if jsonType(raw) != "dict" || json.Unmarshal(raw, &obj) != nil {
		return nil, validationError{"non_field_errors": {"Invalid data. Expected a dictionary, but got " + jsonType(raw) + "."}}
	}
	return obj, nil
}

func nullableRelation(tx *gorm.DB, raw json.RawMessage, table string) (*int64, []string, error) {
	if jsonType(raw) == "NoneType" {
		return nil, nil, nil
	}
	id, msgs := relatedID(raw)
	if len(msgs) > 0 {
		return nil, msgs, nil
	}
	var n int64
	if err := tx.Table(table).Where("id = ?", id).Count(&n).Error; err != nil {
		return nil, nil, err
	}
	if n == 0 {
		return nil, []string{fmt.Sprintf("Invalid pk \"%d\" - object does not exist.", id)}, nil
	}
	return &id, nil, nil
}

// validateOrg is ClientSerializer/SiteSerializer.run_validation. cur is nil on
// create (all required fields enforced) and the stored row on partial update.
func validateOrg(tx *gorm.DB, input map[string]json.RawMessage, site bool, cur *orgRecord, pendingClient bool) (orgRecord, error) {
	var rec orgRecord
	create := cur == nil
	if !create {
		rec = *cur
	} else {
		rec.FailingChecks = json.RawMessage(`{"error": false, "warning": false}`)
	}
	problems := validationError{}
	nameSet := false
	if raw, ok := input["name"]; ok {
		if name, msgs := charField(raw, 255, false, false); len(msgs) > 0 {
			problems["name"] = msgs
		} else {
			rec.Name, nameSet = *name, true
			if !site {
				var n int64
				if err := tx.Table("clients_client").Where("name = ? AND id <> ?", rec.Name, rec.ID).Count(&n).Error; err != nil {
					return rec, err
				}
				if n > 0 {
					problems["name"] = []string{"client with this name already exists."}
				}
			}
		}
	} else if create {
		problems["name"] = []string{"This field is required."}
	}
	clientSet := false
	if site {
		if raw, ok := input["client"]; ok {
			if jsonType(raw) == "NoneType" {
				problems["client"] = []string{"This field may not be null."}
			} else if id, msgs, err := nullableRelation(tx, raw, "clients_client"); err != nil {
				return rec, err
			} else if len(msgs) > 0 {
				problems["client"] = msgs
			} else {
				rec.ClientID, clientSet = *id, true
			}
		} else if create && !pendingClient {
			problems["client"] = []string{"This field is required."}
		}
	}
	if raw, ok := input["block_policy_inheritance"]; ok {
		if v, msgs := booleanField(raw); len(msgs) > 0 {
			problems["block_policy_inheritance"] = msgs
		} else {
			rec.BlockPolicyInheritance = v
		}
	}
	if raw, ok := input["failing_checks"]; ok {
		if jsonType(raw) == "NoneType" {
			problems["failing_checks"] = []string{"This field may not be null."}
		} else {
			rec.FailingChecks = raw
		}
	}
	for field, target := range map[string]struct {
		dst   **int64
		table string
	}{
		"workstation_policy": {&rec.WorkstationPolicyID, "automation_policy"},
		"server_policy":      {&rec.ServerPolicyID, "automation_policy"},
		"alert_template":     {&rec.AlertTemplateID, "alerts_alerttemplate"},
	} {
		if raw, ok := input[field]; ok {
			id, msgs, err := nullableRelation(tx, raw, target.table)
			if err != nil {
				return rec, err
			}
			if len(msgs) > 0 {
				problems[field] = msgs
			} else {
				*target.dst = id
			}
		}
	}
	if len(problems) > 0 {
		return rec, problems
	}
	// site (client, name) UniqueTogetherValidator; on update only changed values count.
	if site && (clientSet || nameSet) && (create || (clientSet && rec.ClientID != cur.ClientID) || (nameSet && rec.Name != cur.Name)) {
		var n int64
		if err := tx.Table("clients_site").Where("client_id = ? AND name = ? AND id <> ?", rec.ClientID, rec.Name, rec.ID).Count(&n).Error; err != nil {
			return rec, err
		}
		if n > 0 {
			return rec, validationError{"non_field_errors": {"The fields client, name must make a unique set."}}
		}
	}
	if nameSet && strings.Contains(rec.Name, "|") {
		kind := "Client"
		if site {
			kind = "Site"
		}
		return rec, validationError{"non_field_errors": {kind + " name cannot contain the | character"}}
	}
	return rec, nil
}

// insertOrg mimics BaseAuditModel.save for a new client/site: the audit value is
// serialized before pk and created/modified fields exist.
func insertOrg(tx *gorm.DB, c fiber.Ctx, site bool, rec orgRecord, view string) (orgRecord, error) {
	actor := principal(c).User.Username
	if err := audit.Write(tx, audit.Entry{Username: actor, ObjectType: objectType(site), Action: "add",
		Message: actor + " added " + objectType(site) + " " + rec.Name, AfterValue: rec.audit(site), DebugInfo: debugInfo(c, view, map[string]any{})}); err != nil {
		return rec, err
	}
	now := time.Now().UTC()
	rec.CreatedBy, rec.ModifiedBy, rec.CreatedTime, rec.ModifiedTime = &actor, &actor, &now, &now
	cols, marks, args := "created_by, created_time, modified_by, modified_time, name, block_policy_inheritance, failing_checks, workstation_policy_id, server_policy_id, alert_template_id",
		"?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?", []any{actor, now, actor, now, rec.Name, rec.BlockPolicyInheritance, string(rec.FailingChecks), rec.WorkstationPolicyID, rec.ServerPolicyID, rec.AlertTemplateID}
	if site {
		cols, marks, args = cols+", client_id", marks+", ?", append(args, rec.ClientID)
	}
	err := tx.Raw("INSERT INTO "+orgTable(site)+" ("+cols+") VALUES ("+marks+") RETURNING id", args...).Scan(&rec.ID).Error
	return rec, orgWriteError(err, site)
}

func orgWriteError(err error, site bool) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		if site {
			return validationError{"non_field_errors": {"The fields client, name must make a unique set."}}
		}
		return validationError{"name": {"client with this name already exists."}}
	}
	return err
}

// updateOrg saves every column like Model.save() and audits only real changes.
// Django serializes the "after" value before modified_by/time are assigned.
func updateOrg(tx *gorm.DB, c fiber.Ctx, site bool, before, after orgRecord, view string, id int64) error {
	actor := principal(c).User.Username
	if b, a := before.audit(site), after.audit(site); !jsonEqual(b, a) {
		if err := audit.Write(tx, audit.Entry{Username: actor, ObjectType: objectType(site), Action: "modify",
			Message: actor + " modified " + objectType(site) + " " + after.Name, BeforeValue: b, AfterValue: a,
			DebugInfo: debugInfo(c, view, map[string]any{"pk": id})}); err != nil {
			return err
		}
	}
	createdBy := after.CreatedBy
	if createdBy == nil || *createdBy == "" {
		createdBy = &actor
	}
	set, args := "created_by = ?, modified_by = ?, modified_time = ?, name = ?, block_policy_inheritance = ?, failing_checks = ?::jsonb, workstation_policy_id = ?, server_policy_id = ?, alert_template_id = ?",
		[]any{createdBy, actor, time.Now().UTC(), after.Name, after.BlockPolicyInheritance, string(after.FailingChecks), after.WorkstationPolicyID, after.ServerPolicyID, after.AlertTemplateID}
	if site {
		set, args = set+", client_id = ?", append(args, after.ClientID)
	}
	return orgWriteError(tx.Exec("UPDATE "+orgTable(site)+" SET "+set+" WHERE id = ?", append(args, id)...).Error, site)
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	var xa, ya any
	_ = json.Unmarshal(x, &xa)
	_ = json.Unmarshal(y, &ya)
	xs, _ := json.Marshal(xa)
	ys, _ := json.Marshal(ya)
	return string(xs) == string(ys)
}

func eqPtr(a, b *int64) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// Django dispatches a Celery task (cache_agents_alert_template) and clears
// Django-cache keys on these changes. Go has no equivalent yet; refuse rather
// than silently leaving agent alert/policy caches stale.
func policyChangeUnsupported(before, after orgRecord, site bool) error {
	if !eqPtr(before.AlertTemplateID, after.AlertTemplateID) || !eqPtr(before.WorkstationPolicyID, after.WorkstationPolicyID) ||
		!eqPtr(before.ServerPolicyID, after.ServerPolicyID) || (site && before.ClientID != after.ClientID) {
		return fiber.NewError(501, "Changing policies, alert templates or a site's client requires Celery cache invalidation, which the Go API does not implement yet.")
	}
	return nil
}

// ---- custom field values on clients/sites ----

type customValue struct {
	field    int64
	str      *string
	strSet   bool
	boolean  bool
	boolSet  bool
	multiple *string // JSON array text, nil = SQL NULL
	multiSet bool
}

func parseCustomValues(tx *gorm.DB, input map[string]json.RawMessage) ([]customValue, error) {
	raw, ok := input["custom_fields"]
	if !ok {
		return nil, nil
	}
	var items []json.RawMessage
	if jsonType(raw) != "list" || json.Unmarshal(raw, &items) != nil {
		return nil, validationError{"custom_fields": {"Expected a list of custom field objects."}}
	}
	out := make([]customValue, 0, len(items))
	for _, item := range items {
		var obj map[string]json.RawMessage
		if jsonType(item) != "dict" || json.Unmarshal(item, &obj) != nil {
			return nil, validationError{"non_field_errors": {"Invalid data. Expected a dictionary, but got " + jsonType(item) + "."}}
		}
		v, problems := customValue{}, validationError{}
		if raw, ok := obj["field"]; !ok {
			problems["field"] = []string{"This field is required."}
		} else if jsonType(raw) == "NoneType" {
			problems["field"] = []string{"This field may not be null."}
		} else if id, msgs, err := nullableRelation(tx, raw, "core_customfield"); err != nil {
			return nil, err
		} else if len(msgs) > 0 {
			problems["field"] = msgs
		} else {
			v.field = *id
		}
		if raw, ok := obj["string_value"]; ok {
			if s, msgs := charField(raw, 1<<30, true, true); len(msgs) > 0 {
				problems["string_value"] = msgs
			} else {
				v.str, v.strSet = s, true
			}
		}
		if raw, ok := obj["bool_value"]; ok {
			if b, msgs := booleanField(raw); len(msgs) > 0 {
				problems["bool_value"] = msgs
			} else {
				v.boolean, v.boolSet = b, true
			}
		}
		if raw, ok := obj["multiple_value"]; ok {
			if arr, msgs := stringList(raw, 1<<30, true); len(msgs) > 0 {
				problems["multiple_value"] = msgs
			} else {
				v.multiple, v.multiSet = arr, true
			}
		}
		if len(problems) > 0 {
			return nil, problems
		}
		out = append(out, v)
	}
	return out, nil
}

// stringList is DRF ListField(child=CharField(allow_null, allow_blank)); it
// returns the JSON array text ready for pgArray, or nil for an allowed null.
func stringList(raw json.RawMessage, maxLength int, nullable bool) (*string, []string) {
	if jsonType(raw) == "NoneType" {
		if nullable {
			return nil, nil
		}
		return nil, []string{"This field may not be null."}
	}
	var items []json.RawMessage
	if jsonType(raw) != "list" || json.Unmarshal(raw, &items) != nil {
		return nil, []string{fmt.Sprintf("Expected a list of items but got type \"%s\".", jsonType(raw))}
	}
	values := make([]*string, len(items))
	for i, item := range items {
		s, msgs := charField(item, maxLength, true, true)
		if len(msgs) > 0 {
			return nil, msgs
		}
		values[i] = s
	}
	text, _ := json.Marshal(values)
	out := string(text)
	return &out, nil
}

// pgArray builds a text[] value from JSON array text, preserving NULL elements.
func pgArray(arg *string) (string, []any) {
	return `CASE WHEN ?::jsonb IS NULL THEN NULL ELSE COALESCE((SELECT array_agg(e ORDER BY o) FROM jsonb_array_elements_text(?::jsonb) WITH ORDINALITY AS t(e, o)), '{}') END`, []any{arg, arg}
}

// saveCustomValues is the serializer upsert both PUT views perform.
func saveCustomValues(tx *gorm.DB, site bool, ownerID int64, values []customValue) error {
	table, owner := "clients_clientcustomfield", "client_id"
	if site {
		table, owner = "clients_sitecustomfield", "site_id"
	}
	for _, v := range values {
		var ids []int64
		if err := tx.Raw("SELECT id FROM "+table+" WHERE field_id = ? AND "+owner+" = ? FOR UPDATE", v.field, ownerID).Scan(&ids).Error; err != nil {
			return err
		}
		if len(ids) > 1 {
			return errors.New("multiple custom field values for one field") // Django: MultipleObjectsReturned
		}
		arr, arrArgs := pgArray(v.multiple)
		if len(ids) == 1 {
			var sets []string
			var args []any
			if v.strSet {
				sets, args = append(sets, "string_value = ?"), append(args, v.str)
			}
			if v.boolSet {
				sets, args = append(sets, "bool_value = ?"), append(args, v.boolean)
			}
			if v.multiSet {
				sets, args = append(sets, "multiple_value = "+arr), append(args, arrArgs...)
			}
			if len(sets) == 0 {
				continue
			}
			if err := tx.Exec("UPDATE "+table+" SET "+strings.Join(sets, ", ")+" WHERE id = ?", append(args, ids[0])...).Error; err != nil {
				return err
			}
			continue
		}
		if !v.multiSet {
			empty := "[]"
			v.multiple = &empty
			arr, arrArgs = pgArray(v.multiple)
		}
		args := append([]any{v.field, ownerID, v.str, v.boolean}, arrArgs...)
		if err := tx.Exec("INSERT INTO "+table+" (field_id, "+owner+", string_value, bool_value, multiple_value) VALUES (?, ?, ?, ?, "+arr+")", args...).Error; err != nil {
			return err
		}
	}
	return nil
}

func addToRoleScope(tx *gorm.DB, c fiber.Ctx, site bool, id int64) error {
	role := principal(c).Role
	if role == nil {
		return nil
	}
	table, column := "accounts_role_can_view_clients", "client_id"
	if site {
		table, column = "accounts_role_can_view_sites", "site_id"
	}
	var n int64
	if err := tx.Raw("SELECT count(*) FROM "+table+" WHERE role_id = ?", role.ID).Scan(&n).Error; err != nil || n == 0 {
		return err
	}
	return tx.Exec("INSERT INTO "+table+" (role_id, "+column+") VALUES (?, ?) ON CONFLICT DO NOTHING", role.ID, id).Error
}

// ---- handlers ----

func (s *Server) addClient(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	clientInput, err := subObject(input, "client")
	if err != nil {
		return err
	}
	siteInput, err := subObject(input, "site")
	if err != nil {
		return err
	}
	var initialSettings map[string]any
	if _, ok := input["initialsetup"]; ok {
		// Client management alone must not grant access to global settings.
		if p := principal(c); p.User.IsInstallerUser || !p.Can("can_edit_core_settings") {
			return errForbidden()
		}
		initialSettings, err = initialSetupValues(input)
		if err != nil {
			return err
		}
	}
	var name string
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		client, err := validateOrg(tx, clientInput, false, nil, false)
		if err != nil {
			return err
		}
		// Django validates the site only after saving the client; the client is
		// removed again on failure, so validating first leaves the same end state.
		nameRaw, ok := siteInput["name"]
		if !ok {
			return validationError{"name": {"This field is required."}}
		}
		site, err := validateOrg(tx, map[string]json.RawMessage{"name": nameRaw}, true, nil, true)
		if err != nil {
			return err
		}
		values, err := parseCustomValues(tx, input)
		if err != nil {
			return err
		}
		if client, err = insertOrg(tx, c, false, client, "GetAddClients"); err != nil {
			return err
		}
		site.ClientID = client.ID
		if site, err = insertOrg(tx, c, true, site, "GetAddClients"); err != nil {
			return err
		}
		if initialSettings != nil {
			if err := saveInitialSetup(tx, c, initialSettings); err != nil {
				return err
			}
		}
		if err := saveCustomValues(tx, false, client.ID, values); err != nil {
			return err
		}
		name = client.Name
		return addToRoleScope(tx, c, false, client.ID)
	})
	if err != nil {
		return writeError(c, err)
	}
	return c.JSON(name + " was added")
}

// initialSetupValues uses the same timezone and company-name validation as
// core settings while retaining the first-run frontend's input field names.
func initialSetupValues(input map[string]json.RawMessage) (map[string]any, error) {
	values, problems := map[string]any{}, validationError{}
	for _, key := range []string{"timezone", "companyname"} {
		if _, ok := input[key]; !ok {
			problems[key] = []string{"This field is required."}
		}
	}
	if len(problems) > 0 {
		return nil, problems
	}
	zone, messages := choiceField(input["timezone"], allTimezones...)
	if len(messages) > 0 {
		problems["timezone"] = messages
	} else {
		values["default_time_zone"] = zone
	}
	company, messages := charField(input["companyname"], 255, true, true)
	if len(messages) > 0 {
		problems["companyname"] = messages
	} else {
		values["mesh_company_name"] = company
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return values, nil
}

func saveInitialSetup(tx *gorm.DB, c fiber.Ctx, values map[string]any) error {
	before, err := readCore(tx, true)
	if err != nil {
		return err
	}
	after := make(map[string]any, len(before))
	for key, value := range before {
		after[key] = value
	}
	for key, value := range values {
		after[key] = value
	}
	if !sameJSON(before, after) {
		if err := coreAudit(tx, c, "GetAddClients", "modify", "coresettings", "Global Site Settings", nil, before, after, coreSecretFields); err != nil {
			return err
		}
	}
	// Go reads these settings directly from PostgreSQL; no cached core snapshot
	// or policy/agent dispatch needs invalidation for these two scalar settings.
	return tx.Table(coreSettingsTable).Where("id = ?", before["id"]).Updates(map[string]any{
		"default_time_zone": values["default_time_zone"], "mesh_company_name": values["mesh_company_name"],
		"modified_by": principal(c).User.Username, "modified_time": time.Now().UTC(),
	}).Error
}

func (s *Server) updateClient(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		before, err := loadOrg(tx, false, id, true)
		if err != nil {
			return err
		}
		clientInput, err := subObject(input, "client")
		if err != nil {
			return err
		}
		after, err := validateOrg(tx, clientInput, false, &before, false)
		if err != nil {
			return err
		}
		values, err := parseCustomValues(tx, input)
		if err != nil {
			return err
		}
		if err := policyChangeUnsupported(before, after, false); err != nil {
			return err
		}
		if err := updateOrg(tx, c, false, before, after, "GetUpdateDeleteClient", id); err != nil {
			return err
		}
		return saveCustomValues(tx, false, id, values)
	})
	if err != nil {
		return writeError(c, err)
	}
	return c.JSON("{client} was updated") // sic: Django's missing f-string prefix
}

func (s *Server) addSite(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	siteInput, err := subObject(input, "site")
	if err != nil {
		return err
	}
	db := s.DB.WithContext(c.Context())
	if raw, ok := siteInput["client"]; ok {
		if id, msgs := relatedID(raw); len(msgs) == 0 {
			if err := hasPermOnObject(db, c, false, id); err != nil {
				return err
			}
		} else if p := principal(c); !p.User.IsSuperuser && (p.Role == nil || !p.Role.IsSuperuser) {
			if p.Role != nil && jsonType(raw) == "NoneType" {
				return lookupError(gorm.ErrRecordNotFound, "Client") // get_object_or_404(pk=None)
			}
			return validationError{"client": msgs}
		}
	}
	var name string
	err = db.Transaction(func(tx *gorm.DB) error {
		site, err := validateOrg(tx, siteInput, true, nil, false)
		if err != nil {
			return err
		}
		values, err := parseCustomValues(tx, input)
		if err != nil {
			return err
		}
		if site, err = insertOrg(tx, c, true, site, "GetAddSites"); err != nil {
			return err
		}
		if err := saveCustomValues(tx, true, site.ID, values); err != nil {
			return err
		}
		name = site.Name
		return addToRoleScope(tx, c, true, site.ID)
	})
	if err != nil {
		return writeError(c, err)
	}
	return c.JSON("Site " + name + " was added!")
}

// sameClient compares request.data["site"]["client"] with the stored id the way
// Python's != does for JSON numbers; strings never equal an int.
func sameClient(raw json.RawMessage, id int64) bool {
	t := jsonType(raw)
	if t != "int" && t != "float" {
		return false
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
	return err == nil && f == float64(id)
}

func (s *Server) updateSite(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		before, err := loadOrg(tx, true, id, true)
		if err != nil {
			return err
		}
		siteInput, err := subObject(input, "site")
		if err != nil {
			return err
		}
		if raw, ok := siteInput["client"]; ok && !sameClient(raw, before.ClientID) {
			var n int64
			if err := tx.Raw("SELECT count(*) FROM clients_site WHERE client_id = ?", before.ClientID).Scan(&n).Error; err != nil {
				return err
			}
			if n == 1 {
				return notifyError("A client must have at least one site")
			}
		}
		after, err := validateOrg(tx, siteInput, true, &before, false)
		if err != nil {
			return err
		}
		values, err := parseCustomValues(tx, input)
		if err != nil {
			return err
		}
		if err := policyChangeUnsupported(before, after, true); err != nil {
			return err
		}
		if err := updateOrg(tx, c, true, before, after, "GetUpdateDeleteSite", id); err != nil {
			return err
		}
		return saveCustomValues(tx, true, id, values)
	})
	if err != nil {
		return writeError(c, err)
	}
	return c.JSON("Site was edited")
}

// moveAgents applies the ?move_to_site=<pk> contract shared by both DELETE views.
func moveAgents(tx *gorm.DB, c fiber.Ctx, siteFilter string, arg int64, none string) error {
	var agents int64
	if err := tx.Raw("SELECT count(*) FROM agents_agent WHERE site_id IN ("+siteFilter+")", arg).Scan(&agents).Error; err != nil {
		return err
	}
	if agents == 0 {
		return nil
	}
	target, ok := c.Queries()["move_to_site"]
	if !ok {
		return notifyError(none)
	}
	id, err := strconv.ParseInt(strings.TrimSpace(target), 10, 64)
	if err != nil {
		return lookupError(gorm.ErrRecordNotFound, "Site")
	}
	if _, err := loadOrg(tx, true, id, false); err != nil {
		return err
	}
	if err := hasPermOnObject(tx, c, true, id); err != nil {
		return err
	}
	return tx.Exec("UPDATE agents_agent SET site_id = ? WHERE site_id IN ("+siteFilter+")", id, arg).Error
}

func (s *Server) deleteClient(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	var name string
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		rec, err := loadOrg(tx, false, id, true)
		if err != nil {
			return err
		}
		filter := "SELECT id FROM clients_site WHERE client_id = ?"
		if err := moveAgents(tx, c, filter, id, "Agents exist under this client. There needs to be a site specified to move existing agents to"); err != nil {
			return err
		}
		if err := cascadeDelete(tx, filter, id, false); err != nil {
			return err
		}
		for _, q := range []string{
			"DELETE FROM clients_clientcustomfield WHERE client_id = ?",
			"DELETE FROM qdt_reports_reportrun WHERE client_id = ?",
			"DELETE FROM accounts_role_can_view_clients WHERE client_id = ?",
			"DELETE FROM automation_policy_excluded_clients WHERE client_id = ?",
			"DELETE FROM alerts_alerttemplate_excluded_clients WHERE client_id = ?",
		} {
			if err := tx.Exec(q, id).Error; err != nil {
				return err
			}
		}
		var protected int64
		if err := tx.Raw("SELECT count(*) FROM qdt_inventory_deviceprofile WHERE client_id = ?", id).Scan(&protected).Error; err != nil || protected > 0 {
			return errors.Join(err, errProtected)
		}
		if err := tx.Exec("DELETE FROM clients_client WHERE id = ?", id).Error; err != nil {
			return err
		}
		name = rec.Name
		rec.ID = 0 // the collector clears the pk before BaseAuditModel serializes
		actor := principal(c).User.Username
		return audit.Write(tx, audit.Entry{Username: actor, ObjectType: "client", Action: "delete", Message: actor + " deleted client " + rec.Name,
			BeforeValue: rec.audit(false), DebugInfo: debugInfo(c, "GetUpdateDeleteClient", map[string]any{"pk": id})})
	})
	if err != nil {
		return writeError(c, err)
	}
	return c.JSON(name + " was deleted")
}

func (s *Server) deleteSite(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	var name string
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		rec, err := loadOrg(tx, true, id, true)
		if err != nil {
			return err
		}
		var siblings int64
		if err := tx.Raw("SELECT count(*) FROM clients_site WHERE client_id = ?", rec.ClientID).Scan(&siblings).Error; err != nil {
			return err
		}
		if siblings == 1 {
			return notifyError("A client must have at least 1 site.")
		}
		if err := moveAgents(tx, c, "?", id, "There needs to be a site specified to move the agents to"); err != nil {
			return err
		}
		if err := cascadeDelete(tx, "?", id, true); err != nil {
			return err
		}
		name = rec.Name
		rec.ID = 0
		actor := principal(c).User.Username
		return audit.Write(tx, audit.Entry{Username: actor, ObjectType: "site", Action: "delete", Message: actor + " deleted site " + rec.Name,
			BeforeValue: rec.audit(true), DebugInfo: debugInfo(c, "GetUpdateDeleteSite", map[string]any{"pk": id})})
	})
	if err != nil {
		return writeError(c, err)
	}
	return c.JSON(name + " was deleted")
}

// Django raises ProtectedError/RestrictedError (HTTP 500) for these.
var errProtected = errors.New("protected or restricted related objects exist")

// cascadeDelete removes sites selected by filter (with arg) and everything the
// Django collector would remove or detach with them. Sites do not audit here:
// the collector deletes them without calling Site.delete().
func cascadeDelete(tx *gorm.DB, filter string, arg int64, single bool) error {
	sites := "SELECT id FROM clients_site WHERE id = ?"
	if !single {
		sites = filter
	}
	for _, q := range []string{
		"SELECT count(*) FROM agents_agent WHERE site_id IN (" + sites + ")",        // Agent.site RESTRICT
		"SELECT count(*) FROM qdt_inventory_asset WHERE site_id IN (" + sites + ")", // Asset.site PROTECT
	} {
		var n int64
		if err := tx.Raw(q, arg).Scan(&n).Error; err != nil || n > 0 {
			return errors.Join(err, errProtected)
		}
	}
	for _, q := range []string{
		"UPDATE qdt_inventory_asset SET snmp_device_id = NULL WHERE snmp_device_id IN (SELECT id FROM qdt_snmp_snmpdevice WHERE site_id IN (" + sites + "))",
		"DELETE FROM qdt_snmp_snmpreading WHERE device_id IN (SELECT id FROM qdt_snmp_snmpdevice WHERE site_id IN (" + sites + "))",
		"DELETE FROM qdt_snmp_snmpalert WHERE device_id IN (SELECT id FROM qdt_snmp_snmpdevice WHERE site_id IN (" + sites + "))",
		"DELETE FROM qdt_snmp_snmpdevice_matrix_channels WHERE snmpdevice_id IN (SELECT id FROM qdt_snmp_snmpdevice WHERE site_id IN (" + sites + "))",
		"DELETE FROM qdt_snmp_snmpdevice WHERE site_id IN (" + sites + ")",
		"DELETE FROM clients_sitecustomfield WHERE site_id IN (" + sites + ")",
		"DELETE FROM clients_deployment WHERE site_id IN (" + sites + ")",
		"DELETE FROM accounts_role_can_view_sites WHERE site_id IN (" + sites + ")",
		"DELETE FROM automation_policy_excluded_sites WHERE site_id IN (" + sites + ")",
		"DELETE FROM alerts_alerttemplate_excluded_sites WHERE site_id IN (" + sites + ")",
		"DELETE FROM clients_site WHERE id IN (" + sites + ")",
	} {
		if err := tx.Exec(q, arg).Error; err != nil {
			return err
		}
	}
	return nil
}
