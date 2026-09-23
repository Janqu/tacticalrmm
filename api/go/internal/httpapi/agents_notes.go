package httpapi

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Server) addAgentNote(c fiber.Ctx) error {
	if err := notesPerm(c); err != nil {
		return err
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	var id string
	if json.Unmarshal(input["agent_id"], &id) != nil || id == "" {
		return validationError{"agent_id": {"A non-empty agent ID is required."}}
	}
	pk, err := s.agentPK(c, id)
	if err != nil {
		return err
	}
	if err := s.hasPermOnAgent(c, id); err != nil {
		return err
	}
	raw, ok := input["note"]
	if !ok {
		return c.Status(400).JSON("Cannot add an empty note")
	}
	note, messages := charField(raw, unlimited, true, true)
	if len(messages) > 0 {
		return validationError{"note": messages}
	}
	// Note has no audit hook or background work in Django.
	if err := s.DB.WithContext(c.Context()).Table("agents_note").Create(map[string]any{
		"agent_id": pk, "user_id": principal(c).User.ID, "note": note,
		"entry_time": time.Now().UTC(),
	}).Error; err != nil {
		return err
	}
	return c.JSON("Note added!")
}

func (s *Server) writeAgentNote(c fiber.Ctx) error {
	if err := notesPerm(c); err != nil {
		return err
	}
	pk, err := identifier(c)
	if err != nil {
		return err
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var note struct {
			ID      int64
			AgentID int64
		}
		result := tx.Table("agents_note").Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", pk).Take(&note)
		if result.Error == gorm.ErrRecordNotFound {
			return fiber.NewError(404, "No Note matches the given query.")
		}
		if result.Error != nil {
			return result.Error
		}
		var id string
		if err := tx.Table("agents_agent").Select("agent_id").Where("id = ?", note.AgentID).Scan(&id).Error; err != nil {
			return err
		}
		if err := s.hasPermOnAgent(c, id); err != nil {
			return err
		}
		if c.Method() == fiber.MethodDelete {
			return tx.Exec("DELETE FROM agents_note WHERE id = ?", pk).Error
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		values, problems := map[string]any{}, validationError{}
		if raw, ok := input["note"]; ok {
			value, messages := charField(raw, unlimited, true, true)
			if len(messages) > 0 {
				problems["note"] = messages
			} else {
				values["note"] = value
			}
		}
		for _, field := range []string{"agent", "user"} {
			raw, ok := input[field]
			if !ok {
				continue
			}
			// DRF relational fields normalize an empty string to null.
			var text string
			if json.Unmarshal(raw, &text) == nil && text == "" {
				raw = json.RawMessage("null")
			}
			if field == "agent" && jsonType(raw) == "NoneType" {
				problems[field] = []string{"This field may not be null."}
				continue
			}
			table := "agents_agent"
			if field == "user" {
				table = "accounts_user"
			}
			value, messages, err := nullableRelation(tx, raw, table)
			if err != nil {
				return err
			}
			if len(messages) > 0 {
				problems[field] = messages
			} else {
				values[field+"_id"] = value
			}
		}
		if len(problems) > 0 {
			return problems
		}
		if target, ok := values["agent_id"].(*int64); ok && *target != note.AgentID {
			var targetID string
			if err := tx.Table("agents_agent").Select("agent_id").Where("id = ?", *target).Scan(&targetID).Error; err != nil {
				return err
			}
			// Also authorize the destination: Django only checks the old agent.
			if err := s.hasPermOnAgent(c, targetID); err != nil {
				return err
			}
		}
		if len(values) == 0 {
			return nil
		}
		return tx.Table("agents_note").Where("id = ?", pk).Updates(values).Error
	})
	if err != nil {
		return err
	}
	if c.Method() == fiber.MethodDelete {
		return c.JSON("Note was deleted!")
	}
	return c.JSON("Note edited!")
}
