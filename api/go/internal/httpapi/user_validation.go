package httpapi

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"gorm.io/gorm"
)

const invalidUsername = "Enter a valid username. This value may contain only letters, numbers, and @/./+/-/_ characters."

func validUsername(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && !strings.ContainsRune("_.@+-", r) {
			return false
		}
	}
	return true
}

var emailLocal = regexp.MustCompile("(?i)^(?:[-!#$%&'*+/=?^_`{}|~0-9a-z]+(?:\\.[-!#$%&'*+/=?^_`{}|~0-9a-z]+)*" +
	`|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f!#-\[\]-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")$`)
var emailDomain = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{1,62}[a-z0-9]$`)

func validEmail(value string) bool {
	if value == "" {
		return true
	}
	at := strings.LastIndexByte(value, '@')
	if at < 0 || utf8.RuneCountInString(value) > 320 {
		return false
	}
	// Python's case-insensitive ASCII ranges also accept these Unicode letters.
	fold := strings.NewReplacer("İ", "i", "ı", "i", "ſ", "s", "K", "k")
	if !emailLocal.MatchString(fold.Replace(value[:at])) {
		return false
	}
	domain := value[at+1:]
	if domain == "localhost" || emailDomain.MatchString(fold.Replace(domain)) {
		return true
	}
	if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
		ip := domain[1 : len(domain)-1]
		address, err := netip.ParseAddr(ip)
		return err == nil && address.Zone() == "" && (!address.Is6() || len(ip) <= 39)
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	return err == nil && emailDomain.MatchString(ascii)
}

func accountIP(raw json.RawMessage) (any, []string) {
	if jsonType(raw) == "NoneType" {
		return nil, nil
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return nil, []string{"Enter a valid IPv4 or IPv6 address."}
	}
	if strings.TrimSpace(value) == "" {
		return nil, []string{"This field may not be blank."}
	}
	if strings.Contains(value, ":") {
		address, err := netip.ParseAddr(value)
		if err != nil || utf8.RuneCountInString(value) > 39 {
			return nil, []string{"Enter a valid IPv4 or IPv6 address."}
		}
		return address.WithZone("").Unmap().String(), nil
	}
	text, messages := charField(raw, 39, false, false)
	if text != nil {
		address, err := netip.ParseAddr(*text)
		if err != nil || !address.Is4() {
			messages = append(messages, "Enter a valid IPv4 or IPv6 address.")
		}
	}
	return text, messages
}

func validateAccount(tx *gorm.DB, input map[string]json.RawMessage, id int64) (map[string]any, error) {
	values, problems := map[string]any{}, validationError{}
	for field, raw := range input {
		var value any
		var messages []string
		switch field {
		case "username":
			text, charMessages := charField(raw, 150, false, false)
			if text != nil {
				if !validUsername(*text) {
					messages = append(messages, invalidUsername)
				}
				// PostgreSQL text cannot represent NUL; reject it before querying.
				if !strings.ContainsRune(*text, 0) {
					var count int64
					if err := tx.Table("accounts_user").Where("username = ? AND id <> ?", *text, id).Count(&count).Error; err != nil {
						return nil, err
					}
					if count > 0 {
						messages = append(messages, "A user with that username already exists.")
					}
				}
			}
			messages = append(messages, charMessages...)
			value = text
		case "first_name", "last_name":
			value, messages = charField(raw, 150, false, true)
		case "email":
			text, errs := charField(raw, 254, false, true)
			value, messages = text, errs
			if text != nil && !validEmail(*text) {
				messages = append(messages, "Enter a valid email address.")
			}
		case "date_format":
			value, messages = charField(raw, 30, true, true)
		case "is_active", "block_dashboard_login":
			value, messages = booleanField(raw)
		case "last_login":
			value, messages = datetimeField(raw)
		case "last_login_ip":
			value, messages = accountIP(raw)
		case "role":
			if jsonType(raw) == "NoneType" {
				values["role_id"] = nil
				continue
			}
			roleID, errs := relatedID(raw)
			messages = errs
			if len(messages) == 0 {
				var count int64
				if err := tx.Table("accounts_role").Where("id = ?", roleID).Count(&count).Error; err != nil {
					return nil, err
				}
				if count == 0 {
					messages = []string{fmt.Sprintf("Invalid pk \"%d\" - object does not exist.", roleID)}
				}
				values["role_id"] = roleID
			}
			if len(messages) > 0 {
				problems[field] = messages
			}
			continue
		default:
			continue
		}
		if len(messages) > 0 {
			problems[field] = messages
		} else {
			values[field] = value
		}
	}
	if len(problems) > 0 {
		return nil, problems
	}
	return values, nil
}
