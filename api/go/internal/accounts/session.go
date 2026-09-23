package accounts

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const SessionAge = 14 * 24 * time.Hour
const sessionSalt = "django.contrib.sessions.SessionStoresigner"

type Session struct {
	SessionKey   string `gorm:"primaryKey"`
	SessionData  string
	ExpireDate   time.Time
	CookieMaxAge int  `gorm:"-"`
	BrowserClose bool `gorm:"-"`
}

func (Session) TableName() string { return "django_session" }

func saltedMAC(salt, secret, value string) []byte {
	key := sha256.Sum256([]byte(salt + secret))
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func SessionAuthHash(password, secret string) string {
	return hex.EncodeToString(saltedMAC("django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash", secret, password))
}

func encodeSession(data map[string]any, secret string, now time.Time) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	// Django's JSONSerializer decodes bytes as Latin-1, so emit ASCII JSON.
	var ascii strings.Builder
	for _, r := range string(raw) {
		if r < 128 {
			ascii.WriteRune(r)
		} else if r <= 0xffff {
			fmt.Fprintf(&ascii, "\\u%04x", r)
		} else {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&ascii, "\\u%04x\\u%04x", hi, lo)
		}
	}
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	stamp := ""
	for n := now.Unix(); n > 0; n /= 62 {
		stamp = string(alphabet[n%62]) + stamp
	}
	if stamp == "" {
		stamp = "0"
	}
	value := base64.RawURLEncoding.EncodeToString([]byte(ascii.String())) + ":" + stamp
	return value + ":" + base64.RawURLEncoding.EncodeToString(saltedMAC(sessionSalt, secret, value)), nil
}

func decodeSession(encoded, secret string) map[string]any {
	empty := func() map[string]any { return map[string]any{} }
	if len(encoded) > 256*1024 {
		return empty()
	}
	i := strings.LastIndexByte(encoded, ':')
	if i < 0 {
		return empty()
	}
	sig, err := base64.RawURLEncoding.DecodeString(encoded[i+1:])
	if err != nil || !hmac.Equal(sig, saltedMAC(sessionSalt, secret, encoded[:i])) {
		return empty()
	}
	value, _, ok := strings.Cut(encoded[:i], ":")
	if !ok {
		return empty()
	}
	compressed := strings.HasPrefix(value, ".")
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "."))
	if err != nil {
		return empty()
	}
	if compressed {
		reader, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return empty()
		}
		raw, err = io.ReadAll(io.LimitReader(reader, 256*1024+1))
		_ = reader.Close()
		if err != nil || len(raw) > 256*1024 {
			return empty()
		}
	}
	var data map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&data) != nil || data == nil {
		return empty()
	}
	return data
}

// LoginSession must share the login transaction. Retain same-user sessions,
// rotate anonymous sessions, and flush sessions for a different user/password.
func LoginSession(tx *gorm.DB, user User, cookie, secret string, now time.Time) (Session, error) {
	data := map[string]any{}
	var session Session
	if len(cookie) >= 8 && len(cookie) <= 40 {
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("session_key = ? AND expire_date > ?", cookie, now).First(&session).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return session, err
		}
		if err == nil {
			data = decodeSession(session.SessionData, secret)
		}
	}
	authHash := SessionAuthHash(user.Password, secret)
	id := strconv.FormatInt(user.ID, 10)
	oldID, authenticated := data["_auth_user_id"]
	oldHash, _ := data["_auth_user_hash"].(string)
	reuse := authenticated && oldID == id && hmac.Equal([]byte(oldHash), []byte(authHash))
	if !reuse {
		if authenticated {
			data = map[string]any{}
		}
		if session.SessionKey != "" {
			if err := tx.Delete(&session).Error; err != nil {
				return session, err
			}
		}
		const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
		var key [32]byte
		for i := range key {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return session, err
			}
			key[i] = alphabet[n.Int64()]
		}
		session.SessionKey = string(key[:])
	}
	data["_auth_user_id"], data["_auth_user_backend"], data["_auth_user_hash"] = id, "django.contrib.auth.backends.ModelBackend", authHash
	var err error
	session.SessionData, err = encodeSession(data, secret, now)
	if err != nil {
		return session, err
	}
	session.CookieMaxAge = int(SessionAge.Seconds())
	session.ExpireDate = now.Add(SessionAge)
	switch expiry := data["_session_expiry"].(type) {
	case json.Number:
		seconds, err := expiry.Int64()
		if err != nil || seconds > 1<<32 || seconds < -1<<32 {
			return session, errors.New("invalid session expiry")
		}
		if seconds == 0 {
			session.BrowserClose = true
		} else {
			session.CookieMaxAge = int(seconds)
			session.ExpireDate = now.Add(time.Duration(seconds) * time.Second)
		}
	case string:
		session.ExpireDate, err = time.Parse(time.RFC3339Nano, expiry)
		if err != nil {
			return session, errors.New("invalid session expiry")
		}
		session.CookieMaxAge = int(session.ExpireDate.Sub(now).Seconds())
	}
	if reuse {
		err = tx.Model(&Session{}).Where("session_key = ?", session.SessionKey).Updates(map[string]any{"session_data": session.SessionData, "expire_date": session.ExpireDate}).Error
	} else {
		err = tx.Create(&session).Error
	}
	return session, err
}

func CSRFToken() (string, error) { return randomString(32) }
