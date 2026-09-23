package httpapi

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

type scriptCollector struct {
	FieldID, OwnerID, SiteID, ClientID int64
	Model, Type, Table, OwnerColumn    string
}

func loadScriptCollector(tx *gorm.DB, agentPK, fieldID int64, lock bool) (scriptCollector, error) {
	field, err := loadCustomField(tx, fieldID, lock)
	if err != nil {
		return scriptCollector{}, err
	}
	out := scriptCollector{FieldID: fieldID, Model: field.Model, Type: field.Type}
	switch field.Type {
	case "text", "number", "single", "datetime", "multiple", "checkbox":
	default:
		return out, validationError{"custom_field": {"Unsupported custom field type."}}
	}
	switch field.Model {
	case "agent":
		out.Table, out.OwnerColumn = "agents_agentcustomfield", "agent_id"
	case "site":
		out.Table, out.OwnerColumn = "clients_sitecustomfield", "site_id"
	case "client":
		out.Table, out.OwnerColumn = "clients_clientcustomfield", "client_id"
	default:
		return out, validationError{"custom_field": {"Unsupported custom field model."}}
	}
	query := "SELECT a.id AS agent_id,a.site_id,s.client_id FROM agents_agent a JOIN clients_site s ON s.id=a.site_id WHERE a.id=?"
	if lock {
		query += " FOR UPDATE OF a,s"
	}
	var rows []struct{ AgentID, SiteID, ClientID int64 }
	if err := tx.Raw(query, agentPK).Scan(&rows).Error; err != nil {
		return out, err
	}
	if len(rows) != 1 {
		return out, lookupError(gorm.ErrRecordNotFound, "Agent")
	}
	out.SiteID = rows[0].SiteID
	out.ClientID = rows[0].ClientID
	switch field.Model {
	case "agent":
		out.OwnerID = rows[0].AgentID
	case "site":
		out.OwnerID = rows[0].SiteID
	case "client":
		out.OwnerID = rows[0].ClientID
	}
	if lock && field.Model == "client" {
		var ids []int64
		if err := tx.Raw("SELECT id FROM clients_client WHERE id=? FOR UPDATE", out.OwnerID).Scan(&ids).Error; err != nil {
			return out, err
		}
		if len(ids) != 1 {
			return out, lookupError(gorm.ErrRecordNotFound, "Client")
		}
	}
	var count int64
	if err := tx.Table(out.Table).Where("field_id = ? AND "+out.OwnerColumn+" = ?", fieldID, out.OwnerID).Count(&count).Error; err != nil {
		return out, err
	}
	if count > 1 {
		return out, fiber.NewError(409, "Multiple values exist for this custom field.")
	}
	return out, nil
}

func scriptCollectorValue(reply any, all bool) (string, error) {
	text, ok := reply.(string)
	if !ok || strings.ContainsRune(text, 0) {
		return "", fiber.NewError(502, "Invalid agent reply for script collector.")
	}
	// Python str.strip includes the four ASCII information separators.
	trim := func(text string) string {
		return strings.TrimFunc(text, func(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f })
	}
	text = trim(text)
	if !all {
		if last := strings.LastIndexByte(text, '\n'); last >= 0 {
			text = text[last+1:]
		}
		text = trim(text)
	}
	return text, nil
}

func saveScriptCollector(tx *gorm.DB, agentPK int64, before scriptCollector, value string) error {
	// Other writers have different lock orders. Bound this local operation;
	// contention must never cause remote execution to be retried.
	if err := tx.Exec("SET LOCAL lock_timeout = '5s'").Error; err != nil {
		return err
	}
	current, err := loadScriptCollector(tx, agentPK, before.FieldID, true)
	if err != nil {
		return err
	}
	if current != before {
		return fiber.NewError(409, "The custom field or target changed during script execution.")
	}
	var ids []int64
	if err := tx.Raw("SELECT id FROM "+current.Table+" WHERE field_id=? AND "+current.OwnerColumn+"=? FOR UPDATE", current.FieldID, current.OwnerID).Scan(&ids).Error; err != nil {
		return err
	}
	if len(ids) > 1 {
		return fiber.NewError(409, "Multiple values exist for this custom field.")
	}
	column, expression, args := "string_value", "?", []any{value}
	if current.Type == "checkbox" {
		column, args = "bool_value", []any{value != ""}
	}
	if current.Type == "multiple" {
		encoded, err := json.Marshal(strings.Split(value, ","))
		if err != nil {
			return err
		}
		text := string(encoded)
		column = "multiple_value"
		expression, args = pgArray(&text)
	}
	if len(ids) == 1 {
		return tx.Exec("UPDATE "+current.Table+" SET "+column+"="+expression+" WHERE id=?", append(args, ids[0])...).Error
	}
	// The inactive storage columns use Django model defaults, not field defaults.
	var stringValue any
	boolValue := false
	multiple := "[]"
	switch current.Type {
	case "checkbox":
		boolValue = value != ""
	case "multiple":
		encoded, _ := json.Marshal(strings.Split(value, ","))
		multiple = string(encoded)
	default:
		stringValue = value
	}
	arraySQL, arrayArgs := pgArray(&multiple)
	args = append([]any{current.FieldID, current.OwnerID, stringValue, boolValue}, arrayArgs...)
	return tx.Exec("INSERT INTO "+current.Table+" (field_id,"+current.OwnerColumn+",string_value,bool_value,multiple_value) VALUES (?,?,?, ?,"+arraySQL+")", args...).Error
}
