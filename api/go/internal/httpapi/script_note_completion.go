package httpapi

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func requireScriptNoteCompletion(tx *gorm.DB) error {
	var exists bool
	if err := tx.Raw("SELECT to_regclass('go_script_note_completion') IS NOT NULL").Scan(&exists).Error; err != nil {
		return err
	}
	if !exists {
		return fiber.NewError(501, "Script note completion storage is not installed.")
	}
	return nil
}

func noteCallbackValue(input map[string]json.RawMessage) (any, error) {
	var result map[string]json.RawMessage
	if jsonType(input["script_results"]) != "dict" || json.Unmarshal(input["script_results"], &result) != nil {
		return nil, validationError{"script_results": {"An object with string or null stdout is required for note callbacks."}}
	}
	raw, present := result["stdout"]
	if !present {
		return nil, validationError{"script_results": {"stdout is required for note callbacks."}}
	}
	if jsonType(raw) == "NoneType" {
		return nil, nil
	}
	var text string
	if jsonType(raw) != "str" || json.Unmarshal(raw, &text) != nil || strings.ContainsRune(text, 0) {
		return nil, validationError{"script_results": {"stdout must be a string or null without null characters."}}
	}
	return scriptNoteValue(text)
}

// The caller already holds the owned history lock. The marker survives note
// deletion, so redelivery cannot recreate a note the user intentionally deleted.
func completeScriptNote(tx *gorm.DB, historyID, agentID, userID int64, input map[string]json.RawMessage, updates map[string]any) error {
	if err := requireScriptNoteCompletion(tx); err != nil {
		return err
	}
	note, err := noteCallbackValue(input)
	if err != nil {
		return err
	}
	identity, err := json.Marshal(input)
	if err != nil {
		return err
	}
	var markers []struct {
		AgentID       int64
		Pending, Same bool
	}
	if err := tx.Raw("SELECT agent_id,payload_identity IS NULL AS pending,COALESCE(payload_identity=?::jsonb,false) AS same FROM go_script_note_completion WHERE history_id=? FOR UPDATE", string(identity), historyID).Scan(&markers).Error; err != nil {
		return err
	}
	if len(markers) != 1 {
		return fiber.NewError(501, "Legacy note callbacks without a completion marker are not supported.")
	}
	marker := markers[0]
	if marker.AgentID != agentID {
		return fiber.NewError(409, "The note callback agent changed.")
	}
	if !marker.Pending {
		if marker.Same {
			return nil
		}
		return fiber.NewError(409, "A different note result was already completed.")
	}
	if err := tx.Table("agents_agenthistory").Where("id=?", historyID).Updates(updates).Error; err != nil {
		return err
	}
	var noteID int64
	if err := tx.Raw("INSERT INTO agents_note (agent_id,user_id,note,entry_time) VALUES (?,?,?,?) RETURNING id", agentID, userID, note, time.Now().UTC()).Scan(&noteID).Error; err != nil {
		return err
	}
	return tx.Exec("UPDATE go_script_note_completion SET payload_identity=?::jsonb,note_id=? WHERE history_id=?", string(identity), noteID, historyID).Error
}
