package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

// parser validates one DRF field. The problem is nil, []string, or a
// map[string][]string for ListField child errors.
type parser func(json.RawMessage) (value any, problem any)

// nestedValidation is a DRF error body that may contain per-item errors.
type nestedValidation map[string]any

func (nestedValidation) Error() string { return "request validation failed" }

func coreError(c fiber.Ctx, err error) error {
	var nested nestedValidation
	if errors.As(err, &nested) {
		return c.Status(400).JSON(nested)
	}
	return err
}

const unlimited = 1 << 30

func charSpec(max int, nullable, blank bool) parser {
	return func(raw json.RawMessage) (any, any) {
		value, messages := charField(raw, max, nullable, blank)
		if len(messages) > 0 {
			return nil, messages
		}
		if value == nil {
			return nil, nil
		}
		return *value, nil
	}
}

func boolSpec(raw json.RawMessage) (any, any) {
	value, messages := booleanField(raw)
	if len(messages) > 0 {
		return nil, messages
	}
	return value, nil
}

func choiceSpec(choices ...string) parser {
	return func(raw json.RawMessage) (any, any) {
		value, messages := choiceField(raw, choices...)
		if len(messages) > 0 {
			return nil, messages
		}
		return value, nil
	}
}

func posIntSpec(raw json.RawMessage) (any, any) {
	value, messages := positiveIntegerField(raw)
	if len(messages) > 0 {
		return nil, messages
	}
	return value, nil
}

// readRow returns to_jsonb(row) with DRF-formatted audit timestamps.
func readRow(tx *gorm.DB, table string, id int64, lock bool) (map[string]any, error) {
	query := "SELECT to_jsonb(t) FROM " + table + " t"
	args := []any{}
	if id != 0 {
		query += " WHERE t.id = ?"
		args = append(args, id)
	}
	query += " ORDER BY t.id LIMIT 1"
	if lock {
		query += " FOR UPDATE"
	}
	rows, err := tx.Raw(query, args...).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, gorm.ErrRecordNotFound
	}
	var raw []byte
	if err := rows.Scan(&raw); err != nil {
		return nil, err
	}
	return decodeRow(raw)
}

func decodeRow(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var row map[string]any
	if err := decoder.Decode(&row); err != nil {
		return nil, err
	}
	for _, field := range []string{"created_time", "modified_time"} {
		text, ok := row[field].(string)
		if !ok {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if err != nil {
			return nil, err
		}
		row[field] = *datetime(&parsed)
	}
	return row, nil
}

func listRows(tx *gorm.DB, table string) ([]map[string]any, error) {
	rows, err := tx.Raw("SELECT to_jsonb(t) FROM " + table + " t ORDER BY t.id").Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []map[string]any{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		row, err := decodeRow(raw)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// parseFields validates every present field and collects DRF-style problems.
func parseFields(input map[string]json.RawMessage, parsers map[string]parser) (map[string]any, error) {
	values, problems := map[string]any{}, nestedValidation{}
	for field, parse := range parsers {
		raw, ok := input[field]
		if !ok {
			continue
		}
		value, problem := parse(raw)
		if problem != nil {
			problems[field] = problem
		} else {
			values[field] = value
		}
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return values, nil
}

// redactedCopy hides secrets. The audit still records THAT a secret changed
// because callers only write entries when the unredacted projections differ.
func redactedCopy(value map[string]any, secrets []string) map[string]any {
	if value == nil {
		return nil
	}
	copied := make(map[string]any, len(value))
	for key, item := range value {
		copied[key] = item
	}
	for _, key := range secrets {
		if text, ok := copied[key].(string); ok && text != "" {
			copied[key] = "[redacted]"
		}
	}
	return copied
}

func coreAudit(tx *gorm.DB, c fiber.Ctx, view, action, object, name string, id *int64, before, after map[string]any, secrets []string) error {
	actor := principal(c).User.Username
	kwargs := map[string]any{}
	if id != nil {
		kwargs["pk"] = *id
	}
	verb := map[string]string{"add": "added", "modify": "modified", "delete": "deleted"}[action]
	return audit.Write(tx, audit.Entry{
		Username: actor, Action: action, ObjectType: object,
		BeforeValue: redactedCopy(before, secrets), AfterValue: redactedCopy(after, secrets),
		Message:   fmt.Sprintf("%s %s %s %s", actor, verb, object, name),
		DebugInfo: map[string]any{"url": c.Path(), "method": c.Method(), "view_class": view, "view_func": view, "view_args": []any{}, "view_kwargs": kwargs, "ip": c.IP()},
	})
}

// auditedModel is a BaseAuditModel-backed table with a partial DRF serializer.
type auditedModel struct {
	table, object, label string
	addView, changeView  string
	columns              []string // insertion/update order, excluding audit columns
	parsers              map[string]parser
	defaults             map[string]any
	secrets              []string
}

func (m auditedModel) parsersWithAudit() map[string]parser {
	all := map[string]parser{"created_by": charSpec(255, true, true), "modified_by": charSpec(255, true, true)}
	for key, parse := range m.parsers {
		all[key] = parse
	}
	return all
}

func (m auditedModel) list(s *Server) fiber.Handler {
	return func(c fiber.Ctx) error {
		rows, err := listRows(s.DB.WithContext(c.Context()), m.table)
		if err != nil {
			return err
		}
		return c.JSON(rows)
	}
}

func (m auditedModel) create(s *Server) fiber.Handler {
	return func(c fiber.Ctx) error {
		err := s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
			input, err := jsonObject(c)
			if err != nil {
				return err
			}
			values, err := parseFields(input, m.parsersWithAudit())
			if err != nil {
				return err
			}
			actor, now := principal(c).User.Username, time.Now().UTC()
			instance := map[string]any{}
			for key, value := range m.defaults {
				instance[key] = value
			}
			for key, value := range values {
				instance[key] = value
			}
			// Django serializes for the audit BEFORE filling created_by/modified_by
			// and before the DB fills id and the auto timestamps.
			after := map[string]any{"id": nil, "created_time": nil, "modified_time": nil, "created_by": nil, "modified_by": nil}
			for key, value := range instance {
				after[key] = value
			}
			name, _ := instance["name"].(string)
			if err := coreAudit(tx, c, m.addView, "add", m.object, name, nil, nil, after, m.secrets); err != nil {
				return err
			}
			if text, _ := instance["created_by"].(string); text == "" {
				instance["created_by"] = actor
			}
			instance["modified_by"] = actor
			columns := append([]string{"created_by", "modified_by", "created_time", "modified_time"}, m.columns...)
			instance["created_time"], instance["modified_time"] = now, now
			return insertRow(tx, m.table, columns, instance)
		})
		if err != nil {
			return coreError(c, err)
		}
		return c.JSON("ok")
	}
}

func insertRow(tx *gorm.DB, table string, columns []string, values map[string]any) error {
	names, marks, args := make([]string, len(columns)), make([]string, len(columns)), make([]any, len(columns))
	for i, column := range columns {
		names[i], marks[i], args[i] = `"`+column+`"`, "?", values[column]
	}
	return tx.Exec("INSERT INTO "+table+" ("+strings.Join(names, ",")+") VALUES ("+strings.Join(marks, ",")+")", args...).Error
}

func (m auditedModel) update(s *Server) fiber.Handler {
	return func(c fiber.Ctx) error {
		id, err := identifier(c)
		if err != nil {
			return err
		}
		err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
			before, err := readRow(tx, m.table, id, true)
			if err != nil {
				return lookupError(err, m.label)
			}
			input, err := jsonObject(c)
			if err != nil {
				return err
			}
			values, err := parseFields(input, m.parsersWithAudit())
			if err != nil {
				return err
			}
			actor := principal(c).User.Username
			after := map[string]any{}
			for key, value := range before {
				after[key] = value
			}
			for key, value := range values {
				after[key] = value
			}
			if !reflect.DeepEqual(before, after) {
				name, _ := after["name"].(string)
				if err := coreAudit(tx, c, m.changeView, "modify", m.object, name, &id, before, after, m.secrets); err != nil {
					return err
				}
			}
			createdBy := after["created_by"]
			if text, _ := createdBy.(string); text == "" {
				createdBy = actor
			}
			set := map[string]any{"created_by": createdBy, "modified_by": actor, "modified_time": time.Now().UTC()}
			for _, column := range m.columns {
				set[column] = after[column]
			}
			return tx.Table(m.table).Where("id = ?", id).Updates(set).Error
		})
		if err != nil {
			return coreError(c, err)
		}
		return c.JSON("ok")
	}
}

func (m auditedModel) remove(s *Server) fiber.Handler {
	return func(c fiber.Ctx) error {
		id, err := identifier(c)
		if err != nil {
			return err
		}
		err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
			before, err := readRow(tx, m.table, id, true)
			if err != nil {
				return lookupError(err, m.label)
			}
			if err := tx.Exec("DELETE FROM "+m.table+" WHERE id = ?", id).Error; err != nil {
				return err
			}
			name, _ := before["name"].(string)
			before["id"] = nil // Django serializes the instance after delete cleared its pk.
			return coreAudit(tx, c, m.changeView, "delete", m.object, name, &id, before, nil, m.secrets)
		})
		if err != nil {
			return err
		}
		return c.JSON("ok")
	}
}
