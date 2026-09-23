package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func loginFields(input map[string]json.RawMessage) (string, string, validationError) {
	values := map[string]string{}
	problems := validationError{}
	for _, field := range []string{"username", "password"} {
		raw, exists := input[field]
		if !exists {
			problems[field] = []string{"This field is required."}
			continue
		}
		// Passwords retain whitespace; the shared CharField helper trims it.
		var value string
		switch jsonType(raw) {
		case "NoneType":
			problems[field] = []string{"This field may not be null."}
			continue
		case "str":
			if json.Unmarshal(raw, &value) != nil {
				problems[field] = []string{"Not a valid string."}
				continue
			}
		case "int", "float":
			value = string(raw)
		default:
			problems[field] = []string{"Not a valid string."}
			continue
		}
		if field == "username" {
			value = strings.TrimSpace(value)
		}
		if value == "" {
			problems[field] = []string{"This field may not be blank."}
		}
		if strings.ContainsRune(value, 0) {
			problems[field] = []string{"Null characters are not allowed."}
		}
		values[field] = value
	}
	return values["username"], values["password"], problems
}

func loginIP(c fiber.Ctx) string {
	// Like the default IpWare chain, accept the first XFF address supplied by
	// the reverse proxy. Deployments must strip untrusted forwarding headers.
	value := c.IP()
	if forwarded := c.Get("X-Forwarded-For"); forwarded != "" {
		value = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		return ip.String()
	}
	return ""
}

func loginAudit(tx *gorm.DB, c fiber.Ctx, username, reason string) error {
	action, message := "failed_login", username+" failed to login: "+reason
	if reason == "" {
		action, message = "login", username+" logged in successfully"
	}
	return audit.Write(tx, audit.Entry{Username: username, ObjectType: "user", Action: action, Message: message, DebugInfo: map[string]any{"ip": loginIP(c)}})
}

func (s *Server) login(c fiber.Ctx) error {
	check := c.Path() == "/v2/checkcreds/"
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	username, password, problems := loginFields(input)
	// Audit the supplied (untrimmed) username, as the Django views do.
	auditUsername := username
	if jsonType(input["username"]) == "str" {
		_ = json.Unmarshal(input["username"], &auditUsername)
	}
	if len(problems) > 0 {
		if !check {
			return problems
		}
		if auditUsername != "" {
			if err := loginAudit(s.DB.WithContext(c.Context()), c, auditUsername, "Credentials were rejected"); err != nil {
				return err
			}
		}
		return c.Status(400).JSON("Bad credentials")
	}
	status, response := 400, any("Bad credentials")
	var session accounts.Session
	var csrf string
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var user accounts.User
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("username = ?", username).First(&user).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		valid, upgrade := accounts.VerifyPassword(password, user.Password)
		if upgrade {
			hash, err := accounts.PasswordHash(&password)
			if err != nil {
				return err
			}
			if err := tx.Model(&accounts.User{}).Where("id = ?", user.ID).UpdateColumn("password", hash).Error; err != nil {
				return err
			}
			user.Password = hash
		}
		if !valid || !user.IsActive {
			if check {
				return loginAudit(tx, c, auditUsername, "Credentials were rejected")
			}
			response = validationError{"non_field_errors": {"Unable to log in with provided credentials."}}
			return nil
		}
		if user.BlockDashboardLogin {
			return nil
		}
		var social int64
		if err := tx.Table("socialaccount_socialaccount").Where("user_id = ?", user.ID).Count(&social).Error; err != nil {
			return err
		}
		if social > 0 {
			return nil
		}
		var core struct {
			ID                  int64
			BlockLocalUserLogon bool
		}
		if err := tx.Table("core_coresettings").Order("id").First(&core).Error; err != nil {
			return errors.New("login core settings unavailable")
		}
		if !user.IsSuperuser && core.BlockLocalUserLogon {
			return nil
		}
		secret := ""
		if user.TOTPKey != nil {
			secret = *user.TOTPKey
		}
		if check && secret != "" {
			status, response = 200, fiber.Map{"totp": true}
			return nil
		}
		if !check {
			var code string
			raw, exists := input["twofactor"]
			if !exists {
				response = validationError{"twofactor": {"This field is required."}}
				return nil
			}
			if jsonType(raw) == "str" {
				_ = json.Unmarshal(raw, &code)
			} else {
				code = string(raw)
			}
			if !accounts.VerifyTOTP(secret, code, time.Now()) {
				return loginAudit(tx, c, auditUsername, "Two Factor token rejected")
			}
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		view := "LoginViewV2"
		if check {
			view = "CheckCredsV2"
		}
		if err := saveLoginUser(tx, c, &user, map[string]any{"last_login": now}, view, false); err != nil {
			return err
		}
		if !check {
			if ip := loginIP(c); ip != "" {
				if err := saveLoginUser(tx, c, &user, map[string]any{"last_login_ip": ip, "modified_time": now}, view, true); err != nil {
					return err
				}
			}
			if err := loginAudit(tx, c, auditUsername, ""); err != nil {
				return err
			}
		}
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return err
		}
		token := hex.EncodeToString(raw[:])
		digest, err := accounts.TokenDigest(token)
		if err != nil {
			return err
		}
		ttl := accounts.TokenTTL
		if check {
			ttl = 3 * time.Minute
		}
		expires := now.Add(ttl)
		if err := tx.Create(&accounts.Token{Digest: digest, TokenKey: token[:8], UserID: user.ID, Created: now, Expiry: &expires}).Error; err != nil {
			return err
		}
		if err := saveLoginUser(tx, c, &user, map[string]any{"last_login": time.Now().UTC().Truncate(time.Microsecond)}, view, false); err != nil {
			return err
		}
		session, err = accounts.LoginSession(tx, user, c.Cookies("sessionid"), s.Login.SecretKey, now)
		if err != nil {
			return err
		}
		csrf, err = accounts.CSRFToken()
		if err != nil {
			return err
		}
		body := fiber.Map{"expiry": datetime(&expires), "token": token}
		if check {
			body["totp"] = false
		} else {
			body["username"], body["name"] = user.Username, nil
		}
		status, response = 200, body
		return nil
	})
	if err != nil {
		return err
	}
	if session.SessionKey != "" {
		cookie := &http.Cookie{Name: "sessionid", Value: session.SessionKey, Path: "/", Domain: s.Login.CookieDomain, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
		if !session.BrowserClose {
			cookie.MaxAge, cookie.Expires = session.CookieMaxAge, session.ExpireDate
			if cookie.MaxAge <= 0 {
				cookie.MaxAge = -1
			}
		}
		// fasthttp emits Max-Age instead of Expires when both are set. Django
		// emits both; net/http preserves that wire format and validates values.
		c.Response().Header.Add("Set-Cookie", cookie.String())
		c.Response().Header.Add("Set-Cookie", (&http.Cookie{Name: "csrftoken", Value: csrf, Path: "/", Domain: s.Login.CookieDomain, MaxAge: 31449600, Expires: time.Now().Add(31449600 * time.Second), SameSite: http.SameSiteLaxMode}).String())
		c.Vary("Cookie")
	}
	return c.Status(status).JSON(response)
}

func saveLoginUser(tx *gorm.DB, c fiber.Ctx, user *accounts.User, values map[string]any, view string, full bool) error {
	before := *user
	p, _ := c.Locals("principal").(*accounts.Principal)
	if full && p != nil {
		values["modified_by"] = p.User.Username
		if user.CreatedBy == nil || *user.CreatedBy == "" {
			values["created_by"] = p.User.Username
		}
	}
	if err := tx.Model(&accounts.User{}).Where("id = ?", user.ID).Updates(values).Error; err != nil {
		return err
	}
	if err := tx.First(user, user.ID).Error; err != nil {
		return err
	}
	if p == nil {
		return nil
	}
	old, err := userAuditValue(before)
	if err != nil {
		return err
	}
	next, err := userAuditValue(*user)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(old, next) {
		return nil
	}
	return audit.Write(tx, audit.Entry{Username: p.User.Username, ObjectType: "user", Action: "modify", BeforeValue: old, AfterValue: next, Message: p.User.Username + " modified user " + user.Username,
		DebugInfo: map[string]any{"url": c.Path(), "method": c.Method(), "view_class": view, "view_func": view, "view_args": []any{}, "view_kwargs": map[string]any{}, "ip": loginIP(c)}})
}
