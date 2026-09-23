package httpapi

import (
	"encoding/json"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerScriptReads(app *fiber.App) {
	for _, path := range []string{"/scripts/", "/scripts/:pk<regex(^[0-9]+$)>/"} {
		app.Add([]string{fiber.MethodGet, fiber.MethodHead}, path, s.authenticate,
			requireRead("can_list_scripts", "can_manage_scripts"), s.readScripts)
	}
}

func (s *Server) readScripts(c fiber.Ctx) error {
	// Explicit serializer projection keeps script bodies out of list responses
	// and preserves PostgreSQL array NULLs and nullable array elements.
	fields := "id, name, description, shell, args, category, favorite, default_timeout, syntax, filename, hidden, supported_platforms, run_as_user, env_vars"
	where, args := " WHERE TRUE", []any{}
	detail := c.Params("pk") != ""
	if detail {
		id, err := identifier(c)
		if err != nil {
			return err
		}
		fields += ", script_body, script_hash"
		where, args = " WHERE id = ?", []any{id}
	} else {
		fields += ", script_type"
		// QueryDict.get uses the last occurrence and compares exact strings.
		community, present := lastQuery(c, "showCommunityScripts")
		if present && (community == "" || community == "false") {
			where += " AND script_type = 'userdefined'"
		}
		hidden, _ := lastQuery(c, "showHiddenScripts")
		if hidden != "true" {
			where += " AND hidden = FALSE"
		}
		where += " ORDER BY category"
	}
	rows, err := s.DB.WithContext(c.Context()).Raw(
		"SELECT row_to_json(t) FROM (SELECT "+fields+" FROM scripts_script"+where+") t", args...).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	result := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		result = append(result, raw)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if detail {
		if len(result) == 0 {
			return lookupError(gorm.ErrRecordNotFound, "Script")
		}
		return c.JSON(result[0])
	}
	return c.JSON(result)
}
