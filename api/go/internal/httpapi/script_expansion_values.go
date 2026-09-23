package httpapi

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Python dict insertion order affects json.dumps. Resolvers must preserve it
// explicitly; accepting an unordered Go map would silently change arguments.
type ScriptObjectField struct {
	Key   string
	Value any
}
type ScriptObject []ScriptObjectField

func formatScriptValue(value any, shell string, quotes bool) (string, error) {
	switch value := value.(type) {
	case nil:
		return "", nil
	case string:
		if shell == "powershell" {
			value = strings.ReplaceAll(value, "'", "''")
		}
		if quotes {
			value = "'" + value + "'"
		}
		return value, nil
	case bool:
		if shell == "powershell" {
			if value {
				return "$True", nil
			}
			return "$False", nil
		}
		if value {
			return "1", nil
		}
		return "0", nil
	case []string:
		text := strings.Trim(strings.Join(value, ","), ",")
		if quotes {
			text = "'" + text + "'"
		}
		return text, nil
	case []any:
		items := make([]string, len(value))
		for i, item := range value {
			text, ok := item.(string)
			if !ok {
				return "", ErrUnsupportedScriptExpansion
			}
			items[i] = text
		}
		return formatScriptValue(items, shell, quotes)
	case ScriptObject:
		return scriptJSON(value)
	case map[string]any:
		// Empty/single-key objects have unambiguous ordering.
		if len(value) > 1 {
			return "", ErrUnsupportedScriptExpansion
		}
		object := ScriptObject{}
		for key, item := range value {
			object = append(object, ScriptObjectField{key, item})
		}
		return scriptJSON(object)
	case json.Number:
		if strings.ContainsAny(value.String(), ".eE") {
			n, err := value.Float64()
			if err != nil {
				return "", err
			}
			return scriptFloat(n), nil
		}
		return value.String(), nil
	case int:
		return strconv.Itoa(value), nil
	case int64:
		return strconv.FormatInt(value, 10), nil
	case uint64:
		return strconv.FormatUint(value, 10), nil
	case float64:
		return scriptFloat(value), nil
	default:
		return "", ErrUnsupportedScriptExpansion
	}
}

func scriptFloat(value float64) string {
	if math.IsNaN(value) {
		return "nan"
	}
	if math.IsInf(value, 1) {
		return "inf"
	}
	if math.IsInf(value, -1) {
		return "-inf"
	}
	format := byte('f')
	if n := math.Abs(value); n != 0 && (n < 1e-4 || n >= 1e16) {
		format = 'e'
	}
	text := strconv.FormatFloat(value, format, -1, 64)
	if !strings.ContainsAny(text, ".e") {
		text += ".0"
	}
	return text
}

func scriptJSONString(text string) string {
	var result strings.Builder
	result.WriteByte('"')
	for _, r := range text {
		switch r {
		case '"', '\\':
			result.WriteByte('\\')
			result.WriteRune(r)
		case '\b':
			result.WriteString(`\b`)
		case '\f':
			result.WriteString(`\f`)
		case '\n':
			result.WriteString(`\n`)
		case '\r':
			result.WriteString(`\r`)
		case '\t':
			result.WriteString(`\t`)
		default:
			if r < 32 || r >= 127 {
				if r > 0xffff {
					r -= 0x10000
					fmt.Fprintf(&result, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&1023))
				} else {
					fmt.Fprintf(&result, `\u%04x`, r)
				}
			} else {
				result.WriteRune(r)
			}
		}
	}
	result.WriteByte('"')
	return result.String()
}

func scriptJSON(value any) (string, error) {
	switch value := value.(type) {
	case nil:
		return "null", nil
	case string:
		return scriptJSONString(value), nil
	case bool:
		return strconv.FormatBool(value), nil
	case ScriptObject:
		items := make([]string, 0, len(value))
		for _, field := range value {
			item, err := scriptJSON(field.Value)
			if err != nil {
				return "", err
			}
			items = append(items, scriptJSONString(field.Key)+": "+item)
		}
		return "{" + strings.Join(items, ", ") + "}", nil
	case []any:
		items := make([]string, len(value))
		for i, value := range value {
			item, err := scriptJSON(value)
			if err != nil {
				return "", err
			}
			items[i] = item
		}
		return "[" + strings.Join(items, ", ") + "]", nil
	case float64:
		if math.IsNaN(value) {
			return "NaN", nil
		}
		if math.IsInf(value, 1) {
			return "Infinity", nil
		}
		if math.IsInf(value, -1) {
			return "-Infinity", nil
		}
		return scriptFloat(value), nil
	case json.Number, int, int64, uint64:
		return formatScriptValue(value, "", false)
	default:
		return "", ErrUnsupportedScriptExpansion
	}
}
