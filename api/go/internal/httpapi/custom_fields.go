package httpapi

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

// cfRecord is a core_customfield row; array columns travel as JSON text.
type cfRecord struct {
	ID                    int64
	CreatedBy             *string
	CreatedTime           *time.Time
	ModifiedBy            *string
	ModifiedTime          *time.Time
	Order                 int64 `gorm:"column:order"`
	Model                 string
	Type                  string
	Options               json.RawMessage
	Name                  string
	Required              bool
	DefaultValueString    *string
	DefaultValueBool      bool
	DefaultValuesMultiple json.RawMessage
	HideInUI              bool `gorm:"column:hide_in_ui"`
	HideInSummary         bool `gorm:"column:hide_in_summary"`
}

const cfSelect = `SELECT id, created_by, created_time, modified_by, modified_time, "order", model, type,
	to_jsonb(options) AS options, name, required, default_value_string, default_value_bool,
	to_jsonb(default_values_multiple) AS default_values_multiple, hide_in_ui, hide_in_summary FROM core_customfield`

// view is CustomFieldSerializer(field).data (fields = "__all__").
func (r cfRecord) view() map[string]any {
	raw := func(m json.RawMessage) any {
		if len(m) == 0 {
			return nil
		}
		return m
	}
	v := map[string]any{"id": nil, "created_by": r.CreatedBy, "created_time": datetime(r.CreatedTime),
		"modified_by": r.ModifiedBy, "modified_time": datetime(r.ModifiedTime), "order": r.Order, "model": r.Model,
		"type": r.Type, "options": raw(r.Options), "name": r.Name, "required": r.Required,
		"default_value_string": r.DefaultValueString, "default_value_bool": r.DefaultValueBool,
		"default_values_multiple": raw(r.DefaultValuesMultiple), "hide_in_ui": r.HideInUI, "hide_in_summary": r.HideInSummary}
	if r.ID != 0 {
		v["id"] = r.ID
	}
	return v
}

func jsonText(m json.RawMessage) *string {
	if len(m) == 0 || string(m) == "null" {
		return nil
	}
	s := string(m)
	return &s
}

func loadCustomField(tx *gorm.DB, id int64, lock bool) (cfRecord, error) {
	q := cfSelect + " WHERE id = ?"
	if lock {
		q += " FOR UPDATE"
	}
	var rows []cfRecord
	if err := tx.Raw(q, id).Scan(&rows).Error; err != nil {
		return cfRecord{}, err
	}
	if len(rows) == 0 {
		return cfRecord{}, lookupError(gorm.ErrRecordNotFound, "CustomField")
	}
	return rows[0], nil
}

// validateCustomField is CustomFieldSerializer(partial=True).run_validation.
func validateCustomField(tx *gorm.DB, input map[string]json.RawMessage, cur *cfRecord) (cfRecord, error) {
	create := cur == nil
	rec := cfRecord{Type: "text", Options: json.RawMessage("[]"), DefaultValuesMultiple: json.RawMessage("[]")}
	if !create {
		rec = *cur
	}
	problems := validationError{}
	set := map[string]bool{}
	for field, target := range map[string]*bool{"required": &rec.Required, "default_value_bool": &rec.DefaultValueBool,
		"hide_in_ui": &rec.HideInUI, "hide_in_summary": &rec.HideInSummary} {
		if raw, ok := input[field]; ok {
			if v, msgs := booleanField(raw); len(msgs) > 0 {
				problems[field] = msgs
			} else {
				*target = v
			}
		}
	}
	for field, target := range map[string]*string{"model": &rec.Model, "type": &rec.Type} {
		choices := []string{"client", "site", "agent"}
		if field == "type" {
			choices = []string{"text", "number", "single", "multiple", "checkbox", "datetime"}
		}
		if raw, ok := input[field]; ok {
			if v, msgs := choiceField(raw, choices...); len(msgs) > 0 {
				problems[field] = msgs
			} else {
				*target, set[field] = v, true
			}
		}
	}
	if raw, ok := input["name"]; ok {
		if v, msgs := charField(raw, 100, false, false); len(msgs) > 0 {
			problems["name"] = msgs
		} else {
			rec.Name, set["name"] = *v, true
		}
	}
	if raw, ok := input["order"]; ok {
		if v, msgs := positiveIntegerField(raw); len(msgs) > 0 {
			problems["order"] = msgs
		} else {
			rec.Order = v
		}
	}
	if raw, ok := input["default_value_string"]; ok {
		if v, msgs := charField(raw, 1<<30, true, true); len(msgs) > 0 {
			problems["default_value_string"] = msgs
		} else {
			rec.DefaultValueString = v
		}
	}
	for _, field := range []string{"created_by", "modified_by"} {
		if raw, ok := input[field]; ok {
			v, msgs := charField(raw, 255, true, true)
			switch {
			case len(msgs) > 0:
				problems[field] = msgs
			case field == "created_by":
				rec.CreatedBy = v
			default:
				rec.ModifiedBy = v
			}
		}
	}
	for field, target := range map[string]*json.RawMessage{"options": &rec.Options, "default_values_multiple": &rec.DefaultValuesMultiple} {
		if raw, ok := input[field]; ok {
			text, msgs := stringList(raw, 255, true)
			switch {
			case len(msgs) > 0:
				problems[field] = msgs
			case text == nil:
				*target = nil
			default:
				*target = json.RawMessage(*text)
			}
		}
	}
	if len(problems) > 0 {
		return rec, problems
	}
	// UniqueTogetherValidator(model, name): required on create, changed-only on update.
	if create {
		for _, f := range []string{"model", "name"} {
			if !set[f] {
				problems[f] = []string{"This field is required."}
			}
		}
		if len(problems) > 0 {
			return rec, problems
		}
	}
	if create || (set["model"] && rec.Model != cur.Model) || (set["name"] && rec.Name != cur.Name) {
		var n int64
		if err := tx.Table("core_customfield").Where("model = ? AND name = ? AND id <> ?", rec.Model, rec.Name, rec.ID).Count(&n).Error; err != nil {
			return rec, err
		}
		if n > 0 {
			return rec, validationError{"non_field_errors": {"The fields model, name must make a unique set."}}
		}
	}
	return rec, nil
}

func customFieldWriteError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return validationError{"non_field_errors": {"The fields model, name must make a unique set."}}
	}
	return err
}

func cfArgs(r cfRecord) (arrays [2]string, out []any) {
	for i, m := range []json.RawMessage{r.Options, r.DefaultValuesMultiple} {
		sql, a := pgArray(jsonText(m))
		arrays[i], out = sql, append(out, a...)
	}
	return arrays, out
}

func (s *Server) addCustomField(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		rec, err := validateCustomField(tx, input, nil)
		if err != nil {
			return err
		}
		actor := principal(c).User.Username
		if err := audit.Write(tx, audit.Entry{Username: actor, ObjectType: "customfield", Action: "add", Message: actor + " added customfield " + rec.Name,
			AfterValue: rec.view(), DebugInfo: debugInfo(c, "GetAddCustomFields", map[string]any{})}); err != nil {
			return err
		}
		createdBy := actor
		if rec.CreatedBy != nil && *rec.CreatedBy != "" {
			createdBy = *rec.CreatedBy
		}
		now := time.Now().UTC()
		arrays, arrayArgs := cfArgs(rec)
		args := []any{createdBy, now, actor, now, rec.Order, rec.Model, rec.Type}
		args = append(args, arrayArgs[:2]...)
		args = append(args, rec.Name, rec.Required, rec.DefaultValueString, rec.DefaultValueBool)
		args = append(args, arrayArgs[2:]...)
		args = append(args, rec.HideInUI, rec.HideInSummary)
		return customFieldWriteError(tx.Exec(`INSERT INTO core_customfield (created_by, created_time, modified_by, modified_time, "order", model, type,
			options, name, required, default_value_string, default_value_bool, default_values_multiple, hide_in_ui, hide_in_summary)
			VALUES (?, ?, ?, ?, ?, ?, ?, `+arrays[0]+`, ?, ?, ?, ?, `+arrays[1]+`, ?, ?)`, args...).Error)
	})
	if err != nil {
		return err
	}
	return c.JSON("ok")
}

func (s *Server) updateCustomField(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		before, err := loadCustomField(tx, id, true)
		if err != nil {
			return err
		}
		after, err := validateCustomField(tx, input, &before)
		if err != nil {
			return err
		}
		actor := principal(c).User.Username
		if b, a := before.view(), after.view(); !jsonEqual(b, a) {
			if err := audit.Write(tx, audit.Entry{Username: actor, ObjectType: "customfield", Action: "modify", Message: actor + " modified customfield " + after.Name,
				BeforeValue: b, AfterValue: a, DebugInfo: debugInfo(c, "GetUpdateDeleteCustomFields", map[string]any{"pk": id})}); err != nil {
				return err
			}
		}
		createdBy := actor
		if after.CreatedBy != nil && *after.CreatedBy != "" {
			createdBy = *after.CreatedBy
		}
		arrays, arrayArgs := cfArgs(after)
		args := []any{createdBy, actor, time.Now().UTC(), after.Order, after.Model, after.Type}
		args = append(args, arrayArgs[:2]...)
		args = append(args, after.Name, after.Required, after.DefaultValueString, after.DefaultValueBool)
		args = append(args, arrayArgs[2:]...)
		args = append(args, after.HideInUI, after.HideInSummary, id)
		return customFieldWriteError(tx.Exec(`UPDATE core_customfield SET created_by = ?, modified_by = ?, modified_time = ?, "order" = ?, model = ?, type = ?,
			options = `+arrays[0]+`, name = ?, required = ?, default_value_string = ?, default_value_bool = ?,
			default_values_multiple = `+arrays[1]+`, hide_in_ui = ?, hide_in_summary = ? WHERE id = ?`, args...).Error)
	})
	if err != nil {
		return err
	}
	return c.JSON("ok")
}

func (s *Server) deleteCustomField(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		rec, err := loadCustomField(tx, id, true)
		if err != nil {
			return err
		}
		for _, q := range []string{
			"DELETE FROM clients_clientcustomfield WHERE field_id = ?",
			"DELETE FROM clients_sitecustomfield WHERE field_id = ?",
			"DELETE FROM agents_agentcustomfield WHERE field_id = ?",
			"UPDATE agents_agenthistory SET custom_field_id = NULL WHERE custom_field_id = ?",
			"UPDATE autotasks_automatedtask SET custom_field_id = NULL WHERE custom_field_id = ?",
			"DELETE FROM core_customfield WHERE id = ?",
		} {
			if err := tx.Exec(q, id).Error; err != nil {
				return err
			}
		}
		rec.ID = 0
		actor := principal(c).User.Username
		return audit.Write(tx, audit.Entry{Username: actor, ObjectType: "customfield", Action: "delete", Message: actor + " deleted customfield " + rec.Name,
			BeforeValue: rec.view(), DebugInfo: debugInfo(c, "GetUpdateDeleteCustomFields", map[string]any{"pk": id})})
	})
	if err != nil {
		return err
	}
	return c.JSON("ok")
}

func (s *Server) customFieldList(c fiber.Ctx, model *string) error {
	q := s.DB.WithContext(c.Context()).Raw(cfSelect + " ORDER BY id")
	if model != nil {
		q = s.DB.WithContext(c.Context()).Raw(cfSelect+" WHERE model = ? ORDER BY id", *model)
	}
	rows := []cfRecord{}
	if err := q.Scan(&rows).Error; err != nil {
		return err
	}
	out := make([]map[string]any, len(rows))
	for i, r := range rows {
		out[i] = r.view()
	}
	return c.JSON(out)
}

func (s *Server) readCustomFields(c fiber.Ctx) error {
	if model, ok := c.Queries()["model"]; ok {
		return s.customFieldList(c, &model)
	}
	return s.customFieldList(c, nil)
}

func (s *Server) filterCustomFields(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	raw, ok := input["model"]
	if !ok {
		return c.Status(400).JSON("The request was invalid")
	}
	model := ""
	switch jsonType(raw) {
	case "str":
		_ = json.Unmarshal(raw, &model)
	case "int", "float":
		model = string(raw)
	case "NoneType":
		return c.JSON([]any{}) // filter(model=None) matches no rows
	default:
		return validationError{"model": {"Unsupported filter value."}}
	}
	return s.customFieldList(c, &model)
}

func (s *Server) readCustomField(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	rec, err := loadCustomField(s.DB.WithContext(c.Context()), id, false)
	if err != nil {
		return err
	}
	return c.JSON(rec.view())
}

func (s *Server) registerCustomFields(app *fiber.App) {
	read := []string{fiber.MethodGet, fiber.MethodHead}
	view := requireRead("can_view_customfields", "can_manage_customfields")
	detail := "/core/customfields/:pk<regex(^[0-9]+$)>/"
	app.Add(read, "/core/customfields/", s.authenticate, view, s.readCustomFields)
	app.Patch("/core/customfields/", s.authenticate, require("can_view_customfields"), s.filterCustomFields)
	app.Post("/core/customfields/", s.authenticate, require("can_manage_customfields"), s.addCustomField)
	app.Add(read, detail, s.authenticate, view, s.readCustomField)
	app.Put(detail, s.authenticate, require("can_manage_customfields"), s.updateCustomField)
	app.Delete(detail, s.authenticate, require("can_manage_customfields"), s.deleteCustomField)
}
