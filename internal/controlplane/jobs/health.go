package jobs

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// CheckQueueReady verifies the durable provisioning_jobs queue table is present
// and queryable before the API advertises readiness.
func CheckQueueReady(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return apierr.QueueUnavailable(errors.New("jobs: nil database pool"))
	}
	if _, err := pool.Exec(ctx, `SELECT 1 FROM provisioning_jobs LIMIT 0`); err != nil {
		return apierr.QueueUnavailable(err)
	}
	return nil
}
