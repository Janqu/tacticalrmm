package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/redis/go-redis/v9"
)

type LoginConfig struct {
	SecretKey    string
	CookieDomain string
	Redis        *redis.Client
	// Separate from Django's pickle-serialized cache; all Go workers share it.
	ThrottlePrefix                               string
	CheckMinute, CheckDay, LoginMinute, LoginDay int
}

// Each scope counts independently, including when the other scope rejects.
// Unlike DRF's cache get/set pair, this operation is atomic across workers.
var loginThrottleScript = redis.NewScript(`
local clock = redis.call('TIME')
local now = tonumber(clock[1]) + tonumber(clock[2]) / 1000000
local wait = 0
for i,key in ipairs(KEYS) do
  local duration = tonumber(ARGV[2*i-1])
  local limit = tonumber(ARGV[2*i])
  local history = redis.call('LRANGE', key, 0, -1)
  while #history > 0 and tonumber(history[#history]) <= now-duration do table.remove(history) end
  if #history >= limit then
    wait = math.max(wait, duration-(now-tonumber(history[#history])))
  else
    if #history == 0 then redis.call('DEL',key)
    else redis.call('LTRIM',key,0,#history-1) end
    redis.call('LPUSH',key,tostring(now))
    redis.call('EXPIRE',key,duration)
  end
end
return math.ceil(wait)
`)

func (s *Server) loginThrottle(c fiber.Ctx) error {
	if s.Login.SecretKey == "" || s.Login.Redis == nil {
		return fiber.NewError(503, "Login is not configured.")
	}
	if c.Locals("principal") != nil {
		return c.Next()
	}
	// Match DRF NUM_PROXIES=None. The ingress must replace client-supplied XFF.
	ident := c.IP()
	if forwarded := c.Get("X-Forwarded-For"); forwarded != "" {
		ident = strings.Join(strings.Fields(forwarded), "")
	}
	hash := sha256.Sum256([]byte(ident))
	scope, minute, day := "login", s.Login.LoginMinute, s.Login.LoginDay
	if c.Path() == "/v2/checkcreds/" {
		scope, minute, day = "check_creds", s.Login.CheckMinute, s.Login.CheckDay
	}
	if minute <= 0 {
		minute = 10
	}
	if day <= 0 {
		day = 300
	}
	prefix := s.Login.ThrottlePrefix
	if prefix == "" {
		prefix = "trmm:go:throttle:"
	}
	key := prefix + "{" + scope + ":" + hex.EncodeToString(hash[:]) + "}"
	wait, err := loginThrottleScript.Run(c.Context(), s.Login.Redis, []string{key + ":min", key + ":day"}, 60, minute, 86400, day).Int()
	if err != nil {
		return fiber.NewError(503, "Login rate limiter unavailable.")
	}
	if wait > 0 {
		c.Set("Retry-After", fmt.Sprint(wait))
		unit := "seconds"
		if wait == 1 {
			unit = "second"
		}
		return fiber.NewError(429, fmt.Sprintf("Request was throttled. Expected available in %d %s.", wait, unit))
	}
	return c.Next()
}
