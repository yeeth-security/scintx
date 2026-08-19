package store

import (
	"database/sql"
	"fmt"
	"time"
)

func (s *SQLStore) EnqueueJob(submissionID string) error {
	if submissionID == "" {
		return fmt.Errorf("empty submission id")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(s.q(`
		INSERT INTO jobs (submission_id, status, created_at, attempts)
		VALUES (?, 'pending', ?, 0)
		ON CONFLICT(submission_id) DO NOTHING
	`), submissionID, now)
	return err
}

func (s *SQLStore) DeleteJob(submissionID string) error {
	_, err := s.db.Exec(s.q(`DELETE FROM jobs WHERE submission_id = ?`), submissionID)
	return err
}

func (s *SQLStore) ClaimJob(owner string, lease time.Duration) (string, int, bool, error) {
	if owner == "" {
		return "", 0, false, fmt.Errorf("empty lease owner")
	}
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	now := time.Now().UTC()
	until := now.Add(lease).Format(time.RFC3339Nano)
	nowStr := now.Format(time.RFC3339Nano)

	tx, err := s.db.Begin()
	if err != nil {
		return "", 0, false, err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(s.q(`
		UPDATE jobs
		SET status = 'pending', lease_owner = NULL, lease_until = NULL
		WHERE status = 'leased' AND lease_until IS NOT NULL AND lease_until < ?
	`), nowStr)
	if err != nil {
		return "", 0, false, err
	}

	var id string
	switch s.dialect {
	case dialectPostgres:
		err = tx.QueryRow(s.q(`
			SELECT submission_id FROM jobs
			WHERE status = 'pending'
			ORDER BY created_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		`)).Scan(&id)
	default:
		err = tx.QueryRow(s.q(`
			SELECT submission_id FROM jobs
			WHERE status = 'pending'
			ORDER BY created_at ASC
			LIMIT 1
		`)).Scan(&id)
	}
	if err == sql.ErrNoRows {
		if err := tx.Commit(); err != nil {
			return "", 0, false, err
		}
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}

	res, err := tx.Exec(s.q(`
		UPDATE jobs
		SET status = 'leased', lease_owner = ?, lease_until = ?, attempts = attempts + 1
		WHERE submission_id = ? AND status = 'pending'
	`), owner, until, id)
	if err != nil {
		return "", 0, false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		if err := tx.Commit(); err != nil {
			return "", 0, false, err
		}
		return "", 0, false, nil
	}
	var attempts int
	if err := tx.QueryRow(s.q(`SELECT attempts FROM jobs WHERE submission_id = ?`), id).Scan(&attempts); err != nil {
		return "", 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return "", 0, false, err
	}
	return id, attempts, true, nil
}

func (s *SQLStore) HeartbeatJob(submissionID, owner string, lease time.Duration) (bool, error) {
	if lease <= 0 {
		lease = 2 * time.Minute
	}
	until := time.Now().UTC().Add(lease).Format(time.RFC3339Nano)
	res, err := s.db.Exec(s.q(`
		UPDATE jobs SET lease_until = ?
		WHERE submission_id = ? AND status = 'leased' AND lease_owner = ?
	`), until, submissionID, owner)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *SQLStore) CompleteJob(submissionID, owner string) error {
	if owner == "" {
		_, err := s.db.Exec(s.q(`DELETE FROM jobs WHERE submission_id = ?`), submissionID)
		return err
	}
	res, err := s.db.Exec(s.q(`
		DELETE FROM jobs
		WHERE submission_id = ? AND (lease_owner = ? OR status = 'pending')
	`), submissionID, owner)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Another owner holds it — ignore (our lease may have been stolen after expiry).
		return nil
	}
	return nil
}

func (s *SQLStore) PendingJobCount() (int, error) {
	var n int
	err := s.db.QueryRow(s.q(`
		SELECT COUNT(*) FROM jobs WHERE status IN ('pending', 'leased')
	`)).Scan(&n)
	return n, err
}
