package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"mime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
)

type validationError map[string][]string

func (validationError) Error() string { return "request validation failed" }

func jsonObject(c fiber.Ctx) (map[string]json.RawMessage, error) {
	if len(c.Body()) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	mediaType, _, err := mime.ParseMediaType(c.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, fiber.NewError(415, fmt.Sprintf("Unsupported media type %q in request.", c.Get("Content-Type")))
	}
	decoder := json.NewDecoder(bytes.NewReader(c.Body()))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, fiber.NewError(400, "JSON parse error - Invalid JSON.")
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, fiber.NewError(400, "JSON parse error - Extra data.")
	}
	var input map[string]json.RawMessage
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, validationError{"non_field_errors": {"No data provided"}}
	}
	if err := json.Unmarshal(raw, &input); err != nil || input == nil {
		return nil, validationError{"non_field_errors": {"Invalid data. Expected a dictionary, but got " + jsonType(raw) + "."}}
	}
	return input, nil
}

func booleanField(raw json.RawMessage) (bool, []string) {
	if jsonType(raw) == "NoneType" {
		return false, []string{"This field may not be null."}
	}
	var value string
	if jsonType(raw) == "str" {
		if err := json.Unmarshal(raw, &value); err != nil {
			return false, []string{"Must be a valid boolean."}
		}
	} else {
		value = string(raw)
	}
	switch strings.ToLower(value) {
	case "t", "y", "yes", "true", "on", "1":
		return true, nil
	case "f", "n", "no", "false", "off", "0":
		return false, nil
	}
	if jsonType(raw) == "float" {
		if number, err := strconv.ParseFloat(value, 64); err == nil && (number == 0 || number == 1) {
			return number == 1, nil
		}
	}
	return false, []string{"Must be a valid boolean."}
}

func choiceField(raw json.RawMessage, choices ...string) (string, []string) {
	if jsonType(raw) == "NoneType" {
		return "", []string{"This field may not be null."}
	}
	value := string(raw)
	if jsonType(raw) == "str" {
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", []string{"Not a valid string."}
		}
	}
	if value == "true" {
		value = "True"
	}
	if value == "false" {
		value = "False"
	}
	for _, choice := range choices {
		if value == choice {
			return value, nil
		}
	}
	return "", []string{fmt.Sprintf("\"%s\" is not a valid choice.", value)}
}

func positiveIntegerField(raw json.RawMessage) (int64, []string) {
	if jsonType(raw) == "NoneType" {
		return 0, []string{"This field may not be null."}
	}
	value := string(raw)
	if jsonType(raw) == "str" {
		if err := json.Unmarshal(raw, &value); err != nil {
			return 0, []string{"A valid integer is required."}
		}
		if utf8.RuneCountInString(value) > 1000 {
			return 0, []string{"String value too large."}
		}
	}
	value = strings.TrimSpace(value)
	if dot := strings.LastIndex(value, "."); dot >= 0 && strings.Trim(value[dot+1:], "0") == "" {
		value = value[:dot]
	}
	number, ok := new(big.Int).SetString(value, 10)
	if !ok && jsonType(raw) == "float" {
		if n, parseErr := strconv.ParseFloat(value, 64); parseErr == nil && n == math.Trunc(n) && n >= math.MinInt64 && n < math.MaxInt64 {
			number, ok = big.NewInt(int64(n)), true
		}
	}
	if !ok {
		return 0, []string{"A valid integer is required."}
	}
	if number.Sign() < 0 {
		return 0, []string{"Ensure this value is greater than or equal to 0."}
	}
	if number.Cmp(big.NewInt(2147483647)) > 0 {
		return 0, []string{"Ensure this value is less than or equal to 2147483647."}
	}
	return number.Int64(), nil
}

func jsonType(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "NoneType"
	}
	switch raw[0] {
	case '"':
		return "str"
	case '[':
		return "list"
	case '{':
		return "dict"
	case 't', 'f':
		return "bool"
	default:
		if bytes.ContainsAny(raw, ".eE") {
			return "float"
		}
		return "int"
	}
}

func charField(raw json.RawMessage, maxLength int, nullable, blank bool) (*string, []string) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if nullable {
			return nil, nil
		}
		return nil, []string{"This field may not be null."}
	}
	var value string
	switch jsonType(raw) {
	case "str":
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, []string{"Not a valid string."}
		}
	case "int", "float":
		value = string(raw)
	default:
		return nil, []string{"Not a valid string."}
	}
	value = strings.TrimSpace(value)
	if value == "" && !blank {
		return nil, []string{"This field may not be blank."}
	}
	var messages []string
	if utf8.RuneCountInString(value) > maxLength {
		messages = append(messages, fmt.Sprintf("Ensure this field has no more than %d characters.", maxLength))
	}
	if strings.ContainsRune(value, 0) {
		messages = append(messages, "Null characters are not allowed.")
	}
	return &value, messages
}

const invalidDatetime = "Datetime has wrong format. Use one of these formats instead: YYYY-MM-DDThh:mm[:ss[.uuuuuu]][+HH:MM|-HH:MM|Z]."

func datetimeField(raw json.RawMessage) (*time.Time, []string) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, []string{invalidDatetime}
	}
	for _, format := range []string{time.RFC3339Nano, "2006-01-02T15:04Z07:00", "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05Z07:00", "2006-01-02 15:04:05", "2006-01-02"} {
		if parsed, err := time.Parse(format, value); err == nil {
			parsed = parsed.UTC().Truncate(time.Microsecond)
			return &parsed, nil
		}
	}
	return nil, []string{invalidDatetime}
}

func relatedID(raw json.RawMessage) (int64, []string) {
	typeName := jsonType(raw)
	if typeName == "NoneType" {
		return 0, []string{"This field may not be null."}
	}
	var value string
	if typeName == "str" {
		if err := json.Unmarshal(raw, &value); err != nil {
			return 0, []string{"Incorrect type. Expected pk value, received str."}
		}
	} else {
		value = string(raw)
	}
	if typeName == "str" || typeName == "int" {
		if id, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
			return id, nil
		}
	}
	if typeName == "float" {
		if number, err := strconv.ParseFloat(value, 64); err == nil && number >= -9223372036854775808.0 && number < 9223372036854775808.0 {
			return int64(number), nil
		}
	}
	return 0, []string{fmt.Sprintf("Incorrect type. Expected pk value, received %s.", typeName)}
}
