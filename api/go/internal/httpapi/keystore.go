package httpapi

// Values are audited redacted: keystore entries commonly hold credentials.
var keyStoreModel = auditedModel{
	table: "core_globalkvstore", object: "globalkvstore", label: "GlobalKVStore",
	addView: "GetAddKeyStore", changeView: "UpdateDeleteKeyStore",
	columns:  []string{"name", "value"},
	parsers:  map[string]parser{"name": charSpec(25, false, false), "value": charSpec(unlimited, false, false)},
	defaults: map[string]any{"name": "", "value": ""},
	secrets:  []string{"value"},
}
