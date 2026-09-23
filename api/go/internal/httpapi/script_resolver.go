package httpapi

import (
	"database/sql"
	"errors"
	"strings"

	"gorm.io/gorm"
)

var ErrScriptValueMissing = errors.New("script value was not found")
var ErrScriptValueAmbiguous = errors.New("script value is not unique")

type scriptModelRef struct {
	model string
	id    int64
}

var scriptModelTables = map[string]string{"agent": "agents_agent", "site": "clients_site", "client": "clients_client"}
var scriptModelFields = map[string]map[string]bool{
	"agent":  scriptFieldSet("id agent_id hostname version operating_system plat goarch public_ip total_ram boot_time logged_in_username last_logged_in_user monitoring_type description mesh_node_id overdue_email_alert overdue_text_alert overdue_dashboard_alert offline_time overdue_time check_interval needs_reboot choco_installed time_zone maintenance_mode block_policy_inheritance default_shell default_shell_custom site_id policy_id alert_template_id"),
	"site":   scriptFieldSet("id name client_id block_policy_inheritance workstation_policy_id server_policy_id alert_template_id"),
	"client": scriptFieldSet("id name block_policy_inheritance workstation_policy_id server_policy_id alert_template_id"),
}

func scriptFieldSet(fields string) map[string]bool {
	set := map[string]bool{}
	for _, field := range strings.Fields(fields) {
		set[field] = true
	}
	return set
}

// The caller supplies an already-authorized root and context-bearing DB handle.
// This resolver adds no routes or authorization bypass. It reads only explicit
// scalar fields, Agent.site/client, Site.client, custom fields and global keys.
// It never runs Django properties, returns model objects, or writes DebugLogs.
func newScriptValueResolver(db *gorm.DB, model string, id int64) ScriptValueResolver {
	root := scriptModelRef{model, id}
	return func(expression string) (any, error) {
		parts := strings.Split(strings.TrimSpace(expression), ".")
		if len(parts) == 2 && parts[0] == "global" {
			var rows []struct{ Value string }
			if err := db.Table("core_globalkvstore").Select("value").Where("name = ?", parts[1]).Limit(2).Find(&rows).Error; err != nil {
				return nil, err
			}
			if len(rows) == 0 {
				return nil, ErrScriptValueMissing
			}
			if len(rows) > 1 {
				return nil, ErrScriptValueAmbiguous
			}
			return rows[0].Value, nil
		}
		if _, ok := scriptModelTables[root.model]; !ok || root.id <= 0 {
			return nil, ErrUnsupportedScriptExpansion
		}
		if len(parts) == 2 {
			if _, ok := scriptModelTables[parts[0]]; ok {
				value, found, err := resolveScriptCustomField(db, root, parts[0], parts[1])
				if err != nil || found {
					return value, err
				}
			}
		}
		if parts[0] == root.model {
			parts = parts[1:]
		}
		ref := root
		for i, part := range parts {
			if i == len(parts)-1 {
				if part == "pk" {
					part = "id"
				}
				if !scriptModelFields[ref.model][part] {
					return nil, ErrUnsupportedScriptExpansion
				}
				value, err := scriptScalar(db, ref, part)
				if err != nil {
					return nil, err
				}
				if !pyTruthy(value) || value == float64(0) {
					return nil, nil
				}
				return value, nil
			}
			var err error
			ref, err = scriptRelatedModel(db, ref, part)
			if err != nil {
				return nil, err
			}
		}
		return nil, ErrUnsupportedScriptExpansion
	}
}

func scriptScalar(db *gorm.DB, ref scriptModelRef, field string) (any, error) {
	table, ok := scriptModelTables[ref.model]
	if !ok || !scriptModelFields[ref.model][field] {
		return nil, ErrUnsupportedScriptExpansion
	}
	var raw []byte
	// Both identifiers come exclusively from the fixed allowlists above.
	err := db.Raw("SELECT to_jsonb("+field+") FROM "+table+" WHERE id = ?", ref.id).Row().Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrScriptValueMissing
	}
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	value, err := decodeScriptScalar(raw)
	if err != nil {
		return nil, err
	}
	// PostgreSQL JSON can serialize an integral float as 10; preserve its
	// Python float type so argument formatting still produces "10.0".
	if ref.model == "agent" && field == "boot_time" {
		return scriptScalarFloat(value)
	}
	return value, nil
}

func scriptRelatedModel(db *gorm.DB, ref scriptModelRef, relation string) (scriptModelRef, error) {
	if ref.model == "agent" && relation == "client" {
		site, err := scriptRelatedModel(db, ref, "site")
		if err != nil {
			return scriptModelRef{}, err
		}
		return scriptRelatedModel(db, site, "client")
	}
	if ref.model == "agent" && relation == "site" || ref.model == "site" && relation == "client" {
		value, err := scriptScalar(db, ref, relation+"_id")
		if err != nil {
			return scriptModelRef{}, err
		}
		id, ok := pyInt(value)
		if !ok || id <= 0 {
			return scriptModelRef{}, ErrScriptValueMissing
		}
		return scriptModelRef{relation, id}, nil
	}
	return scriptModelRef{}, ErrUnsupportedScriptExpansion
}
