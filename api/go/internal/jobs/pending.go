package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

const PendingActionsLock int64 = 0x54524d4d50454e44

type PendingOptions struct {
	LatestVersion string
	Now           time.Time
	DryRun        bool
}

type PendingReport struct {
	Job            string `json:"job"`
	Selected       int    `json:"selected"`
	Eligible       int    `json:"eligible"`
	Updated        int64  `json:"updated"`
	DryRun         bool   `json:"dry_run"`
	AlreadyRunning bool   `json:"already_running"`
}

type pendingAgent struct {
	ID          int64
	Version     string
	LastSeen    *time.Time
	OfflineTime int64
	OverdueTime int64
}

// Agent.status intentionally reports online at the exact overdue boundary.
func agentOnline(now time.Time, lastSeen *time.Time, offlineMinutes, overdueMinutes int64) (bool, error) {
	now = now.UTC()
	threshold := func(minutes int64) (time.Time, error) {
		if minutes < 0 || minutes > 2147483647 {
			return time.Time{}, errors.New("invalid agent status threshold")
		}
		value := now.AddDate(0, 0, -int(minutes/1440)).Add(-time.Duration(minutes%1440) * time.Minute)
		if value.Year() < 1 || value.Year() > 9999 {
			return time.Time{}, errors.New("agent status threshold is out of range")
		}
		return value, nil
	}
	offline, err := threshold(offlineMinutes)
	if err != nil {
		return false, err
	}
	overdue, err := threshold(overdueMinutes)
	if err != nil {
		return false, err
	}
	if lastSeen == nil {
		return false, nil
	}
	return !lastSeen.Before(offline) || lastSeen.Equal(overdue), nil
}

// ResolvePendingActions is one bounded, atomic DB-only pass. It never dispatches
// an agent command and never alters scheduled-reboot or other pending actions.
func ResolvePendingActions(ctx context.Context, db *gorm.DB, options PendingOptions) (PendingReport, error) {
	report := PendingReport{Job: "resolve-pending-actions", DryRun: options.DryRun}
	latest, err := canonicalVersion(options.LatestVersion)
	if err != nil {
		return report, errors.New("invalid configured latest agent version")
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Year() < 1 || now.Year() > 9999 {
		return report, errors.New("job time is out of range")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var acquired bool
		if err := tx.Raw("SELECT pg_try_advisory_xact_lock(?)", PendingActionsLock).Scan(&acquired).Error; err != nil {
			return errors.New("acquire pending action job lock")
		}
		if !acquired {
			report.AlreadyRunning = true
			return nil
		}
		if err := tx.Exec("SET LOCAL lock_timeout = '5s'").Error; err != nil {
			return errors.New("configure job lock timeout")
		}
		if err := tx.Exec("SET LOCAL statement_timeout = '25s'").Error; err != nil {
			return errors.New("configure job statement timeout")
		}
		// Lock both the pending status and the agent fields used to decide eligibility.
		// The stable order also avoids duplicate-agent lock inversions between runs.
		var rows []pendingAgent
		if err := tx.Raw(`SELECT p.id,a.version,a.last_seen,a.offline_time,a.overdue_time
   FROM logs_pendingaction p JOIN agents_agent a ON a.id=p.agent_id
   WHERE p.action_type='agentupdate' AND p.status='pending'
   ORDER BY a.id,p.id FOR UPDATE OF p,a`).Scan(&rows).Error; err != nil {
			return errors.New("read pending agent updates")
		}
		report.Selected = len(rows)
		ids := []int64{}
		for _, row := range rows {
			version, err := canonicalVersion(row.Version)
			if err != nil {
				return fmt.Errorf("invalid agent version for pending action %d", row.ID)
			}
			if version != latest {
				continue
			}
			online, err := agentOnline(now, row.LastSeen, row.OfflineTime, row.OverdueTime)
			if err != nil {
				return fmt.Errorf("invalid status timing for pending action %d", row.ID)
			}
			if online {
				ids = append(ids, row.ID)
			}
		}
		report.Eligible = len(ids)
		if options.DryRun || len(ids) == 0 {
			return nil
		}
		result := tx.Table("logs_pendingaction").Where("id IN ? AND action_type = ? AND status = ?", ids, "agentupdate", "pending").Update("status", "completed")
		if result.Error != nil {
			return errors.New("complete pending agent updates")
		}
		report.Updated = result.RowsAffected
		return nil
	})
	if err != nil {
		report.Updated = 0
		return report, err
	}
	return report, nil
}
