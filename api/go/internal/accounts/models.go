package accounts

import "time"

// These projections use the existing Django schema. Do not embed gorm.Model:
// Django uses different timestamps and does not soft-delete these records.
type User struct {
	ID                  int64      `gorm:"primaryKey" json:"id"`
	Username            string     `json:"username"`
	Password            string     `json:"-"`
	FirstName           string     `json:"first_name"`
	LastName            string     `json:"last_name"`
	Email               string     `json:"email"`
	IsActive            bool       `json:"is_active"`
	IsSuperuser         bool       `json:"-"`
	IsInstallerUser     bool       `json:"-"`
	AgentID             *int64     `json:"-"`
	RoleID              *int64     `json:"role"`
	BlockDashboardLogin bool       `json:"block_dashboard_login"`
	TOTPKey             *string    `gorm:"column:totp_key" json:"-"`
	LastLogin           *time.Time `json:"last_login"`
	LastLoginIP         *string    `gorm:"column:last_login_ip" json:"last_login_ip"`
	DateFormat          *string    `json:"date_format"`
	CreatedBy           *string    `json:"-"`
	ModifiedBy          *string    `json:"-"`
	CreatedTime         *time.Time `json:"-"`
	ModifiedTime        *time.Time `json:"-"`
}

func (User) TableName() string { return "accounts_user" }

type Token struct {
	Digest   string     `gorm:"primaryKey" json:"digest"`
	TokenKey string     `json:"-"`
	UserID   int64      `json:"-"`
	Created  time.Time  `json:"created"`
	Expiry   *time.Time `json:"expiry"`
}

func (Token) TableName() string { return "knox_authtoken" }

type APIKey struct {
	ID           int64 `gorm:"primaryKey"`
	Name         string
	Key          string
	Expiration   *time.Time
	UserID       int64
	CreatedBy    *string
	ModifiedBy   *string
	CreatedTime  *time.Time
	ModifiedTime *time.Time
}

func (APIKey) TableName() string { return "accounts_apikey" }
