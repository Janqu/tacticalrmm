package httpapi

var urlActionModel = auditedModel{
	table: "core_urlaction", object: "urlaction", label: "URLAction",
	addView: "GetAddURLAction", changeView: "UpdateDeleteURLAction",
	columns: []string{"name", "desc", "pattern", "action_type", "rest_method", "rest_body", "rest_headers"},
	parsers: map[string]parser{
		"name": charSpec(255, false, false), "desc": charSpec(unlimited, true, true),
		"pattern":     charSpec(unlimited, false, false),
		"action_type": choiceSpec("web", "rest"), "rest_method": choiceSpec("get", "post", "put", "delete", "patch"),
		"rest_body": charSpec(unlimited, true, true), "rest_headers": charSpec(unlimited, true, true),
	},
	// The serializer is partial, so omitted required fields take model defaults.
	defaults: map[string]any{"name": "", "desc": nil, "pattern": "", "action_type": "web", "rest_method": "post", "rest_body": "", "rest_headers": ""},
}
