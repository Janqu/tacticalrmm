package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"

	"gorm.io/gorm"
)

func decodeScriptScalar(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	err := decoder.Decode(&value)
	return value, err
}

func scriptScalarFloat(value any) (any, error) {
	if number, ok := value.(json.Number); ok {
		return number.Float64()
	}
	return nil, ErrUnsupportedScriptExpansion
}

func resolveScriptCustomField(db *gorm.DB, root scriptModelRef, model, name string) (any, bool, error) {
	var rows []struct{ Raw json.RawMessage }
	err := db.Table("core_customfield f").Select("to_jsonb(f) AS raw").Where("model = ? AND name = ?", model, name).Limit(2).Find(&rows).Error
	if err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	if len(rows) > 1 {
		return nil, true, ErrScriptValueAmbiguous
	}
	field, err := decodeRow(rows[0].Raw)
	if err != nil {
		return nil, true, err
	}
	column, defaultColumn := "string_value", "default_value_string"
	switch field["type"] {
	case "text", "number", "single", "datetime":
	case "multiple":
		column, defaultColumn = "multiple_value", "default_values_multiple"
	case "checkbox":
		column, defaultColumn = "bool_value", "default_value_bool"
	default:
		return nil, true, ErrUnsupportedScriptExpansion
	}
	fallback := field[defaultColumn]
	if field["type"] == "checkbox" {
		fallback = pyTruthy(fallback)
	}
	target := root
	if target.model != model {
		target, err = scriptRelatedModel(db, root, model)
		if errors.Is(err, ErrUnsupportedScriptExpansion) {
			// Source custom-field lookup falls back to its default when this
			// root has no relation to the field's model (e.g. Client -> Agent).
			return fallback, true, nil
		}
		if err != nil {
			return nil, true, err
		}
	}
	tables := map[string]string{"agent": "agents_agentcustomfield", "site": "clients_sitecustomfield", "client": "clients_clientcustomfield"}
	table, ok := tables[model]
	if !ok {
		return nil, true, ErrUnsupportedScriptExpansion
	}
	rows = nil
	err = db.Table(table).Select("to_jsonb("+column+") AS raw").Where("field_id = ? AND "+model+"_id = ?", field["id"], target.id).Limit(2).Find(&rows).Error
	if err != nil {
		return nil, true, err
	}
	if len(rows) == 0 {
		return fallback, true, nil
	}
	if len(rows) > 1 {
		return nil, true, ErrScriptValueAmbiguous
	}
	var value any
	if rows[0].Raw != nil {
		value, err = decodeScriptScalar(rows[0].Raw)
		if err != nil {
			return nil, true, err
		}
	}
	if field["type"] == "checkbox" {
		return pyTruthy(value), true, nil
	}
	if !pyTruthy(value) {
		return fallback, true, nil
	}
	return value, true, nil
}
