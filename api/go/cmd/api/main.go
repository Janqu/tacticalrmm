package main

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/amidaware/tacticalrmm/api/go/internal/database"
	"github.com/amidaware/tacticalrmm/api/go/internal/httpapi"
	"github.com/gofiber/fiber/v3"
	"github.com/redis/go-redis/v9"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		// Connection errors can include a DSN, so do not print the raw error.
		logger.Error("API stopped", "reason", safeReason(err))
		os.Exit(1)
	}
}

var errConfiguration = errors.New("invalid configuration: verify database, login, Redis, NATS and script settings")

func safeReason(err error) string {
	if errors.Is(err, errConfiguration) {
		return errConfiguration.Error()
	}
	return "startup or listener failure; verify database connectivity and listen address"
}

func run(logger *slog.Logger) error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	db, err := database.Open(ctx, dsn)
	cancel()
	if err != nil {
		return err
	}
	pool, err := db.DB()
	if err != nil {
		return err
	}
	defer pool.Close()
	var origins []string
	for _, origin := range strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ",") {
		if origin = strings.TrimSpace(origin); origin != "" {
			origins = append(origins, origin)
		}
	}
	secretKey := os.Getenv("API_SECRET_KEY")
	if secretKey == "" {
		secretKey = os.Getenv("DJANGO_SECRET_KEY") // Existing installations retain their signing key.
	}
	login := httpapi.LoginConfig{SecretKey: secretKey, CookieDomain: os.Getenv("SESSION_COOKIE_DOMAIN"), ThrottlePrefix: os.Getenv("LOGIN_THROTTLE_PREFIX")}
	redisURL := os.Getenv("REDIS_URL")
	if (login.SecretKey == "") != (redisURL == "") {
		return errConfiguration
	}
	if redisURL != "" {
		options, err := redis.ParseURL(redisURL)
		if err != nil {
			return errConfiguration
		}
		options.ContextTimeoutEnabled = true
		login.Redis = redis.NewClient(options)
		defer login.Redis.Close()
		pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = login.Redis.Ping(pingCtx).Err()
		pingCancel()
		if err != nil {
			return err
		}
	}
	for name, value := range map[string]*int{
		"TRMM_CHECK_CREDS_MIN_THROTTLE": &login.CheckMinute, "TRMM_CHECK_CREDS_DAY_THROTTLE": &login.CheckDay,
		"TRMM_LOGIN_MIN_THROTTLE": &login.LoginMinute, "TRMM_LOGIN_DAY_THROTTLE": &login.LoginDay,
	} {
		if raw := os.Getenv(name); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n <= 0 || n > 10000 {
				return errConfiguration
			}
			*value = n
		}
	}
	var cache *redis.Client
	if cacheURL := os.Getenv("DJANGO_CACHE_REDIS_URL"); cacheURL != "" {
		options, err := redis.ParseURL(cacheURL)
		if err != nil {
			return errConfiguration
		}
		options.ContextTimeoutEnabled = true
		cache = redis.NewClient(options)
		defer cache.Close()
	}
	var bus *agentbus.Client
	if address := os.Getenv("NATS_URL"); address != "" {
		endpoint, err := url.Parse(address)
		if err != nil || endpoint.Hostname() == "" || (endpoint.Scheme != "nats" && endpoint.Scheme != "tls") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "" {
			return errConfiguration
		}
		user, password := os.Getenv("NATS_USER"), os.Getenv("NATS_PASSWORD")
		if user == "" {
			user = "tacticalrmm"
		}
		if password == "" {
			password = secretKey
		}
		if password == "" {
			return errConfiguration
		}
		bus = &agentbus.Client{URL: address, User: user, Password: password}
	}
	scriptConfig, err := scriptRuntimeConfig()
	if err != nil {
		return err
	}
	scriptConfig.Origins, scriptConfig.Login = origins, login
	scriptConfig.RootUser, scriptConfig.Cache, scriptConfig.NATS = os.Getenv("ROOT_USER"), cache, bus
	scriptConfig.LatestAgentVersion = os.Getenv("LATEST_AGENT_VER")
	app := httpapi.New(db, logger, scriptConfig)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	address := os.Getenv("LISTEN_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	logger.Info("starting API", "address", address)
	return app.Listen(address, fiber.ListenConfig{
		GracefulContext:       ctx,
		ShutdownTimeout:       15 * time.Second,
		DisableStartupMessage: true,
	})
}

func scriptRuntimeConfig() (httpapi.Config, error) {
	var config httpapi.Config
	if raw, present := os.LookupEnv("NUSHELL_ENABLE_CONFIG"); present {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return config, errConfiguration
		}
		config.NushellEnableConfig = value
	}
	if value, present := os.LookupEnv("DENO_DEFAULT_PERMISSIONS"); present {
		config.DenoDefaultPermissions = &value
	}
	return config, nil
}
