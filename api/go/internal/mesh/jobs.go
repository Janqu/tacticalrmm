package mesh

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

// Enqueue must use the mutation's transaction. A generation is retained even
// after completion, so a delayed worker cannot acknowledge a newer request.
func Enqueue(tx *gorm.DB) error {
	return tx.Exec(`INSERT INTO go_mesh_sync (id, generation) VALUES (1, 1)
		ON CONFLICT (id) DO UPDATE SET generation = go_mesh_sync.generation + 1,
		requested_at = CURRENT_TIMESTAMP, next_attempt_at = CURRENT_TIMESTAMP, attempts = 0`).Error
}

// ProcessPending performs at most one full reconciliation. Remote writes are
// at-least-once: a crash before acknowledgement leaves the generation pending.
func ProcessPending(ctx context.Context, db *gorm.DB, baseURL string) (bool, error) {
	var job struct{ Generation int64 }
	result := db.WithContext(ctx).Table("go_mesh_sync").
		Where("id = 1 AND generation > completed_generation AND next_attempt_at <= CURRENT_TIMESTAMP").Take(&job)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if result.Error != nil {
		return false, errors.New("read pending MeshCentral synchronization")
	}
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	_, err := Run(runCtx, db, baseURL, false)
	if errors.Is(err, ErrAlreadyRunning) {
		return false, nil
	}
	if err != nil {
		// A newer request must not inherit an older generation's retry delay.
		retry := db.WithContext(ctx).Exec(`UPDATE go_mesh_sync SET attempts = attempts + 1,
			next_attempt_at = CURRENT_TIMESTAMP + INTERVAL '30 seconds'
			WHERE id = 1 AND generation = ? AND completed_generation < ?`, job.Generation, job.Generation)
		if retry.Error != nil {
			return true, errors.Join(err, errors.New("schedule MeshCentral retry"))
		}
		return true, err
	}
	if err := db.WithContext(ctx).Exec(`UPDATE go_mesh_sync
		SET completed_generation = GREATEST(completed_generation, ?)
		WHERE id = 1`, job.Generation).Error; err != nil {
		return true, errors.New("acknowledge MeshCentral synchronization")
	}
	return true, nil
}
