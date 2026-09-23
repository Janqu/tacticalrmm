package audit

import (
	"bytes"
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// Entry maps Django's audit log. Values must be explicit safe projections,
// never entire account models, request bodies or credentials.
type Entry struct {
	ID          int64 `gorm:"primaryKey"`
	Username    string
	Agent       *string
	AgentID     *string
	EntryTime   time.Time
	Action      string
	ObjectType  string
	BeforeValue map[string]any `gorm:"serializer:json;type:jsonb"`
	AfterValue  any            `gorm:"serializer:json;type:jsonb"`
	Message     string
	DebugInfo   map[string]any `gorm:"serializer:json;type:jsonb"`
}

func (Entry) TableName() string { return "logs_auditlog" }

// Write uses the caller's transaction so the mutation and its audit commit together.
func Write(tx *gorm.DB, entry Entry) error {
	// Django's default AUDIT_MAX_VALUE_BYTES is 512 KiB per JSON field.
	entry.BeforeValue = boundedValue(entry.BeforeValue).(map[string]any)
	entry.AfterValue = boundedValue(entry.AfterValue)
	entry.DebugInfo = boundedValue(entry.DebugInfo).(map[string]any)
	entry.EntryTime = time.Now().UTC()
	message := []rune(entry.Message)
	if len(message) > 255 {
		entry.Message = string(message[:253]) + ".."
	}
	return tx.Create(&entry).Error
}

func boundedValue(input any) any {
	raw, err := json.Marshal(input)
	if err != nil {
		return map[string]any{"error": "could not process audit value"}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return map[string]any{"error": "could not process audit value"}
	}
	if pythonJSONSize(value) > 512*1024 {
		return map[string]any{"error": "value too large to store in audit log. Check documentation for configuring AUDIT_MAX_VALUE_BYTES"}
	}
	return input
}

// json.dumps uses ASCII escapes and spaces after separators; compact UTF-8 JSON
// would undercount large Unicode script bodies relative to Django's limit.
func pythonJSONSize(value any) int {
	switch v := value.(type) {
	case nil:
		return 4
	case bool:
		if v {
			return 4
		}
		return 5
	case json.Number:
		return len(v)
	case string:
		n := 2
		for _, r := range v {
			switch {
			case r == '"' || r == '\\' || r == '\b' || r == '\f' || r == '\n' || r == '\r' || r == '\t':
				n += 2
			case r > 0xffff:
				n += 12
			case r < 32 || r >= 127:
				n += 6
			default:
				n++
			}
		}
		return n
	case []any:
		n := 2
		for i, item := range v {
			if i > 0 {
				n += 2
			}
			n += pythonJSONSize(item)
		}
		return n
	case map[string]any:
		n, i := 2, 0
		for key, item := range v {
			if i > 0 {
				n += 2
			}
			n += pythonJSONSize(key) + 2 + pythonJSONSize(item)
			i++
		}
		return n
	}
	panic("audit size requires decoded JSON")
}
