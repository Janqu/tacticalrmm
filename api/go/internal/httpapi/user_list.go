package httpapi

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
)

type socialAccountRow struct {
	UserID     int64
	UID        string `gorm:"column:uid"`
	Provider   string
	LastLogin  time.Time
	DateJoined time.Time
	ExtraData  json.RawMessage
}

type socialAccountResponse struct {
	UID        string          `json:"uid"`
	Provider   string          `json:"provider"`
	Display    string          `json:"display"`
	LastLogin  *string         `json:"last_login"`
	DateJoined *string         `json:"date_joined"`
	ExtraData  json.RawMessage `json:"extra_data"`
}

type socialAppRow struct {
	Provider   string
	ProviderID string
	Name       string
	Settings   json.RawMessage
}

func (s *Server) users(c fiber.Ctx) error {
	db := s.DB.WithContext(c.Context())
	query := db.Where("agent_id IS NULL AND is_installer_user = ?", false)
	// QueryDict.get takes the last repeated value; PostgreSQL's UPPER matches
	// Django's icontains, and escaping keeps %, _ and backslash literal.
	var search string
	c.Request().URI().QueryArgs().VisitAll(func(key, value []byte) {
		if string(key) == "search" {
			search = string(value)
		}
	})
	if search != "" {
		search = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(search)
		query = query.Where("UPPER(username::text) LIKE UPPER(?)", "%"+search+"%")
	}
	var users []accounts.User
	if err := query.Find(&users).Error; err != nil {
		return err
	}
	type response struct {
		userResponse
		SocialAccounts []socialAccountResponse `json:"social_accounts"`
	}
	result := make([]response, 0, len(users))
	if len(users) == 0 {
		return c.JSON(result)
	}
	ids := make([]int64, 0, len(users))
	for _, user := range users {
		ids = append(ids, user.ID)
	}
	var social []socialAccountRow
	if err := db.Table("socialaccount_socialaccount").Where("user_id IN ?", ids).Find(&social).Error; err != nil {
		return err
	}
	var apps []socialAppRow
	if len(social) > 0 {
		if err := db.Table("socialaccount_socialapp").Select("provider, provider_id, name, settings").Find(&apps).Error; err != nil {
			return err
		}
	}
	byUser := make(map[int64][]socialAccountResponse)
	for _, account := range social {
		byUser[account.UserID] = append(byUser[account.UserID], socialAccountResponse{
			UID: account.UID, Provider: account.Provider, Display: socialDisplay(account, apps),
			LastLogin: datetime(&account.LastLogin), DateJoined: datetime(&account.DateJoined), ExtraData: account.ExtraData,
		})
	}
	for _, user := range users {
		result = append(result, response{userResponse{User: user, LastLogin: datetime(user.LastLogin)}, append([]socialAccountResponse{}, byUser[user.ID]...)})
	}
	return c.JSON(result)
}

func socialDisplay(account socialAccountRow, apps []socialAppRow) string {
	var matches []socialAppRow
	for _, app := range apps {
		if app.Provider == account.Provider || app.ProviderID == account.Provider {
			matches = append(matches, app)
		}
	}
	if len(matches) == 0 {
		return "Orphaned Provider"
	}
	if len(matches) > 1 {
		visible := make([]socialAppRow, 0, len(matches))
		for _, app := range matches {
			var settings map[string]any
			if json.Unmarshal(app.Settings, &settings) != nil || settings == nil {
				return "Unknown"
			}
			if !jsonTruthy(settings["hidden"]) {
				visible = append(visible, app)
			}
		}
		if len(visible) != 1 {
			return "Unknown"
		}
		matches = visible
	}
	// Tactical RMM installs only this allauth provider. Unknown providers must
	// not display metadata as though provider resolution had succeeded.
	if account.Provider != "openid_connect" && matches[0].Provider != "openid_connect" {
		return "Unknown"
	}
	var data map[string]any
	if json.Unmarshal(account.ExtraData, &data) != nil {
		return matches[0].Name
	}
	groups := [][]string{
		{"username", "userName", "user_name", "login", "handle"},
		{"email", "Email", "mail", "email_address"},
		{"name", "display_name", "displayName", "displayname", "Display_Name", "nickname"},
		{"full_name", "fullName"},
		{"first_name", "firstname", "firstName", "First_Name", "given_name", "givenName"},
		{"last_name", "lastname", "lastName", "Last_Name", "family_name", "familyName", "surname"},
	}
	var names [2]string
	for i, keys := range groups {
		for _, key := range keys {
			if value, ok := data[key].(string); ok {
				value = strings.TrimFunc(value, func(r rune) bool { return unicode.IsSpace(r) || r >= '\x1c' && r <= '\x1f' })
				if i < 4 && value != "" {
					return value
				}
				if i >= 4 {
					names[i-4] = value
				}
			}
		}
	}
	if name := strings.TrimSpace(names[0] + " " + names[1]); name != "" {
		return name
	}
	return matches[0].Name
}

func jsonTruthy(value any) bool {
	switch value := value.(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != ""
	case float64:
		return value != 0
	case []any:
		return len(value) != 0
	case map[string]any:
		return len(value) != 0
	default:
		return true
	}
}
