package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/database"
	"github.com/amidaware/tacticalrmm/api/go/internal/mesh"
)

func run() error {
	dryRun := flag.Bool("dry-run", false, "show planned changes without modifying MeshCentral")
	worker := flag.Bool("worker", false, "process durable MeshCentral synchronization requests")
	once := flag.Bool("once", false, "with --worker, process at most one pending generation and exit")
	flag.Parse()
	if (*dryRun && *worker) || (*once && !*worker) {
		return fmt.Errorf("--dry-run cannot be combined with --worker; --once requires --worker")
	}
	if raw := os.Getenv("TRMM_DISABLE_MESH_SYNC_TASK"); raw != "" {
		disabled, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("invalid TRMM_DISABLE_MESH_SYNC_TASK")
		}
		if disabled {
			return nil
		}
	}
	if os.Getenv("DATABASE_URL") == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	db, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL")
	}
	pool, err := db.DB()
	if err != nil {
		return fmt.Errorf("get PostgreSQL pool")
	}
	defer pool.Close()
	baseURL := os.Getenv("MESH_WS_URL")
	if baseURL == "" {
		baseURL = "ws://127.0.0.1:4430"
	}
	if *worker {
		for {
			processed, err := mesh.ProcessPending(ctx, db, baseURL)
			if ctx.Err() != nil {
				return nil
			}
			if *once {
				return err
			}
			if err != nil {
				slog.Error("MeshCentral worker failed; request retained", "error", err)
			}
			if processed && err == nil {
				continue
			}
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	changes, err := mesh.Run(ctx, db, baseURL, *dryRun)
	if err != nil {
		return err
	}
	if *dryRun {
		return json.NewEncoder(os.Stdout).Encode(changes)
	}
	fmt.Printf("MeshCentral synchronization complete: %d changes\n", len(changes))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
