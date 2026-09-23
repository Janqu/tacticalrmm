package httpapi

import (
	"encoding/json"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type scriptSnippetRow struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	Code  string `json:"code"`
	Shell string `json:"shell"`
}

func (s *Server) registerScriptSnippetRoutes(app *fiber.App) {
	base := "/scripts/snippets/"
	detail := base + ":pk<regex(^[0-9]+$)>/"
	for _, path := range []string{base, detail} {
		app.Add([]string{fiber.MethodGet, fiber.MethodHead}, path, s.authenticate,
			requireRead("can_list_scripts", "can_manage_scripts"), s.readScriptSnippets)
	}
	app.Post(base, s.authenticate, require("can_manage_scripts"), s.writeScriptSnippet)
	app.Add([]string{fiber.MethodPut, fiber.MethodDelete}, detail, s.authenticate,
		require("can_manage_scripts"), s.writeScriptSnippet)
}

func (s *Server) readScriptSnippets(c fiber.Ctx) error {
	query := s.DB.WithContext(c.Context()).Table("scripts_scriptsnippet")
	detail := c.Params("pk") != ""
	if detail {
		id, err := identifier(c)
		if err != nil {
			return err
		}
		query = query.Where("id = ?", id)
	}
	rows := []scriptSnippetRow{}
	if err := query.Select(`id,name,"desc",code,shell`).Order("id").Find(&rows).Error; err != nil {
		return err
	}
	if detail {
		if len(rows) == 0 {
			return lookupError(gorm.ErrRecordNotFound, "ScriptSnippet")
		}
		return c.JSON(rows[0])
	}
	return c.JSON(rows)
}

// Snippet code uses DRF CharField(trim_whitespace=False). Unlike the name and
// description, surrounding spaces and newlines are part of the stored program.
func snippetCode(raw json.RawMessage) (string, []string) {
	text, problems := charField(raw, unlimited, false, true)
	if len(problems) > 0 {
		return "", problems
	}
	if jsonType(raw) == "str" {
		var original string
		if err := json.Unmarshal(raw, &original); err != nil {
			return "", []string{"Not a valid string."}
		}
		text = &original
	}
	if *text == "" {
		return "", []string{"This field may not be blank."}
	}
	return *text, nil
}

func validateScriptSnippet(tx *gorm.DB, input map[string]json.RawMessage, row scriptSnippetRow, create bool) (scriptSnippetRow, error) {
	problems := validationError{}
	if raw, ok := input["name"]; ok {
		name, messages := charField(raw, 40, false, false)
		if len(messages) > 0 {
			problems["name"] = messages
		} else {
			row.Name = *name
			var count int64
			if err := tx.Table("scripts_scriptsnippet").Where("name = ? AND id <> ?", row.Name, row.ID).Count(&count).Error; err != nil {
				return row, err
			}
			if count > 0 {
				problems["name"] = []string{"script snippet with this name already exists."}
			}
		}
	} else if create {
		problems["name"] = []string{"This field is required."}
	}
	if raw, ok := input["desc"]; ok {
		text, messages := charField(raw, 50, false, true)
		if len(messages) > 0 {
			problems["desc"] = messages
		} else {
			row.Desc = *text
		}
	}
	if raw, ok := input["code"]; ok {
		text, messages := snippetCode(raw)
		if len(messages) > 0 {
			problems["code"] = messages
		} else {
			row.Code = text
		}
	}
	if raw, ok := input["shell"]; ok {
		text, messages := choiceField(raw, "powershell", "cmd", "python", "shell", "nushell", "deno")
		if len(messages) > 0 {
			problems["shell"] = messages
		} else {
			row.Shell = text
		}
	}
	if len(problems) > 0 {
		return row, problems
	}
	return row, nil
}

func (s *Server) writeScriptSnippet(c fiber.Ctx) error {
	create := c.Method() == fiber.MethodPost
	var id int64
	if !create {
		var err error
		id, err = identifier(c)
		if err != nil {
			return err
		}
	}
	err := s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		row := scriptSnippetRow{Shell: "powershell"}
		if !create {
			if err := tx.Table("scripts_scriptsnippet").Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id).Take(&row).Error; err != nil {
				return lookupError(err, "ScriptSnippet")
			}
		}
		if c.Method() == fiber.MethodDelete {
			return tx.Exec("DELETE FROM scripts_scriptsnippet WHERE id = ?", id).Error
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		row, err = validateScriptSnippet(tx, input, row, create)
		if err != nil {
			return err
		}
		// Plain Django Model: snippet writes do not create BaseAuditModel entries.
		if create {
			return tx.Table("scripts_scriptsnippet").Create(&row).Error
		}
		return tx.Table("scripts_scriptsnippet").Where("id = ?", id).Updates(map[string]any{"name": row.Name, "desc": row.Desc, "code": row.Code, "shell": row.Shell}).Error
	})
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return validationError{"name": {"script snippet with this name already exists."}}
		}
		return err
	}
	if c.Method() == fiber.MethodDelete {
		return c.JSON("Script snippet was deleted successfully")
	}
	return c.JSON("Script snippet was saved successfully")
}
