package accounts

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
)

const TokenTTL = 5 * time.Hour

type AuthError struct{ Detail string }

func (e *AuthError) Error() string { return e.Detail }

type Principal struct {
	User  User
	Role  *Role
	Token *Token
}

func (p *Principal) Can(permission string) bool {
	return p.User.IsSuperuser || (p.Role != nil && (p.Role.IsSuperuser || p.Role.Allows(permission)))
}

type Authenticator struct{ DB *gorm.DB }

// Knox hashes the decoded hex bytes, not the textual representation of the token.
func TokenDigest(token string) (string, error) {
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) == 0 {
		return "", &AuthError{"Invalid token."}
	}
	digest := sha512.Sum512(decoded)
	return hex.EncodeToString(digest[:]), nil
}

func (a *Authenticator) Authenticate(ctx context.Context, authorization, apiKey string, tokenOnly bool) (*Principal, error) {
	parts := strings.Fields(authorization)
	isToken := len(parts) > 0 && strings.EqualFold(parts[0], "Token")
	if !isToken && (apiKey == "" || tokenOnly) {
		return nil, &AuthError{"Authentication credentials were not provided."}
	}
	db := a.DB.WithContext(ctx)
	now := time.Now().UTC()
	var principal Principal
	switch {
	case isToken:
		if len(parts) == 1 {
			return nil, &AuthError{"Invalid token header. No credentials provided."}
		}
		if len(parts) > 2 {
			return nil, &AuthError{"Invalid token header. Token string should not contain spaces."}
		}
		token, err := findToken(db, parts[1], now)
		if err != nil {
			return nil, err
		}
		// Match Knox AUTO_REFRESH and MIN_REFRESH_INTERVAL, including setup tokens.
		if token.Expiry != nil {
			expiry := now.Add(TokenTTL)
			if expiry.Sub(*token.Expiry) > 10*time.Minute {
				if err := db.Model(token).Update("expiry", expiry).Error; err != nil {
					return nil, err
				}
			}
			token.Expiry = &expiry
		}
		principal.Token = token
		principal.User.ID = token.UserID
	case apiKey != "" && !tokenOnly:
		var key APIKey
		if err := db.Where("key = ?", apiKey).First(&key).Error; err != nil {
			return nil, authLookupError(err)
		}
		// User activity is checked before API-key expiration, as in Django.
		if err := db.First(&principal.User, key.UserID).Error; err != nil {
			return nil, authLookupError(err)
		}
		if !principal.User.IsActive {
			return nil, &AuthError{"User inactive or deleted."}
		}
		if key.Expiration != nil && key.Expiration.Before(now) {
			return nil, &AuthError{"The token has expired."}
		}
	default:
		return nil, &AuthError{"Authentication credentials were not provided."}
	}
	if principal.Token != nil {
		if err := db.First(&principal.User, principal.User.ID).Error; err != nil {
			return nil, authLookupError(err)
		}
	}
	if !principal.User.IsActive {
		return nil, &AuthError{"User inactive or deleted."}
	}
	if principal.User.RoleID != nil {
		var role Role
		if err := db.First(&role, *principal.User.RoleID).Error; err != nil {
			return nil, err
		}
		principal.Role = &role
	}
	return &principal, nil
}

func findToken(db *gorm.DB, raw string, now time.Time) (*Token, error) {
	var candidates []Token
	if err := db.Where("token_key = ?", raw[:min(8, len(raw))]).Find(&candidates).Error; err != nil {
		return nil, err
	}
	for _, token := range candidates {
		// Knox cleans every candidate user's expired tokens, even on a prefix
		// collision or malformed credential. Preserve these database effects.
		if err := db.Where("user_id = ? AND expiry < ?", token.UserID, now).Delete(&Token{}).Error; err != nil {
			return nil, err
		}
		if token.Expiry != nil && token.Expiry.Before(now) {
			continue
		}
		digest, err := TokenDigest(raw)
		if err != nil {
			return nil, err
		}
		if hmac.Equal([]byte(digest), []byte(token.Digest)) {
			return &token, nil
		}
	}
	return nil, &AuthError{"Invalid token."}
}

func authLookupError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &AuthError{"Invalid token."}
	}
	return err
}
