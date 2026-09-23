package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/amidaware/tacticalrmm/api/go/internal/database"
	"github.com/amidaware/tacticalrmm/api/go/internal/httpapi"
	"github.com/amidaware/tacticalrmm/api/go/internal/jobs"
)

func envTruthy(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func run() error {
	job := flag.String("job", "", "one-shot job: resolve-pending-actions | auto-approve-win-updates")
	latest := flag.String("latest-agent-version", os.Getenv("LATEST_AGENT_VER"), "configured latest agent version")
	dryRun := flag.Bool("dry-run", false, "report eligible work without changing state or publishing")
	at := flag.String("now", "", "explicit RFC3339 job clock; defaults to current UTC time")
	scanPause := flag.Duration("scan-pause", time.Second, "pause between auto-approve scan chunks of 40")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	now := time.Now().UTC()
	if *at != "" {
		var err error
		now, err = time.Parse(time.RFC3339Nano, *at)
		if err != nil {
			return errors.New("--now must be RFC3339")
		}
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch *job {
	case "resolve-pending-actions":
		if *latest == "" {
			return errors.New("--latest-agent-version or LATEST_AGENT_VER is required")
		}
		ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
		defer cancel()
		db, err := database.Open(ctx, dsn)
		if err != nil {
			return errors.New("connect to PostgreSQL")
		}
		pool, err := db.DB()
		if err != nil {
			return errors.New("get PostgreSQL pool")
		}
		defer pool.Close()
		report, err := jobs.ResolvePendingActions(ctx, db, jobs.PendingOptions{LatestVersion: *latest, Now: now, DryRun: *dryRun})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)

	case "auto-approve-win-updates":
		if *scanPause < 0 {
			return errors.New("--scan-pause must not be negative")
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Minute+30*time.Second)
		defer cancel()
		db, err := database.Open(ctx, dsn)
		if err != nil {
			return errors.New("connect to PostgreSQL")
		}
		pool, err := db.DB()
		if err != nil {
			return errors.New("get PostgreSQL pool")
		}
		defer pool.Close()
		var bus *agentbus.Client
		if url := strings.TrimSpace(os.Getenv("NATS_URL")); url != "" && !*dryRun && !envTruthy("TRMM_DISABLE_APPROVE_UPDATES_TASK") {
			bus = &agentbus.Client{URL: url, User: os.Getenv("NATS_USER"), Password: os.Getenv("NATS_PASSWORD")}
		}
		if pauseEnv := strings.TrimSpace(os.Getenv("TRMM_WINUPDATE_APPROVE_SCAN_PAUSE_MS")); pauseEnv != "" {
			ms, err := strconv.Atoi(pauseEnv)
			if err != nil || ms < 0 {
				return errors.New("TRMM_WINUPDATE_APPROVE_SCAN_PAUSE_MS must be a non-negative integer")
			}
			*scanPause = time.Duration(ms) * time.Millisecond
		}
		report, err := jobs.AutoApproveUpdates(ctx, db, bus, jobs.AutoApproveOptions{
			Now:       now,
			DryRun:    *dryRun,
			Disabled:  envTruthy("TRMM_DISABLE_APPROVE_UPDATES_TASK"),
			ScanPause: *scanPause,
			Prune:     httpapi.PruneSupersededUpdates,
			Approve:   httpapi.ApproveAgentUpdatesBackground,
		})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)

	default:
		return errors.New("--job resolve-pending-actions|auto-approve-win-updates is required")
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
