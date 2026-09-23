package accounts

import (
	"context"
	"strings"
	"unicode/utf8"

	"gorm.io/gorm"
)

// Agent callbacks use DRF's persistent token table, never Knox or API keys.
type AgentTokenPrincipal struct {
	UserID   int64
	AgentID  *int64
	IsActive bool
}

func agentTokenHeader(authorization string) (string, error) {
	parts := strings.FieldsFunc(authorization, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '\v' || r == '\f' })
	if len(parts) == 0 || !strings.EqualFold(parts[0], "Token") {
		return "", &AuthError{"Authentication credentials were not provided."}
	}
	if len(parts) == 1 {
		return "", &AuthError{"Invalid token header. No credentials provided."}
	}
	if len(parts) > 2 {
		return "", &AuthError{"Invalid token header. Token string should not contain spaces."}
	}
	if !utf8.ValidString(parts[1]) {
		return "", &AuthError{"Invalid token header. Token string should not contain invalid characters."}
	}
	return parts[1], nil
}

func AuthenticateAgentToken(ctx context.Context, db *gorm.DB, authorization string) (*AgentTokenPrincipal, error) {
	key, err := agentTokenHeader(authorization)
	if err != nil {
		return nil, err
	}
	var user AgentTokenPrincipal
	err = db.WithContext(ctx).Table("authtoken_token t").Joins("JOIN accounts_user u ON u.id=t.user_id").Select("u.id AS user_id,u.agent_id,u.is_active").Where("t.key = ?", key).Take(&user).Error
	if err != nil {
		return nil, authLookupError(err)
	}
	if !user.IsActive {
		return nil, &AuthError{"User inactive or deleted."}
	}
	return &user, nil
}
