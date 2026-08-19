package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/yeeth-security/scintx/api"
	"github.com/yeeth-security/scintx/internal/scintx"
)

func (s *SQLStore) PutSubmission(sub *api.Submission) error {
	if sub == nil {
		return nil
	}
	body, err := json.Marshal(sub)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(s.q(`
		INSERT INTO submissions (id, body) VALUES (?, ?)
		ON CONFLICT(id) DO UPDATE SET body = excluded.body
	`), sub.ID, string(body))
	return err
}

func (s *SQLStore) GetSubmission(id string) (*api.Submission, bool, error) {
	var body string
	err := s.db.QueryRow(s.q(`SELECT body FROM submissions WHERE id = ?`), id).Scan(&body)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var sub api.Submission
	if err := json.Unmarshal([]byte(body), &sub); err != nil {
		return nil, false, err
	}
	return &sub, true, nil
}

func (s *SQLStore) PutSubmissionIdempotent(key, requestHash string, sub *api.Submission) (*api.Submission, bool, error) {
	if sub == nil {
		return nil, false, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()

	if key != "" {
		var existingID, existingHash string
		err := tx.QueryRow(s.q(`SELECT submission_id, request_hash FROM idempotency WHERE key = ?`), key).
			Scan(&existingID, &existingHash)
		if err == nil {
			if existingHash != "" && requestHash != "" && existingHash != requestHash {
				return nil, false, scintx.ErrIdempotencyConflict
			}
			var body string
			err = tx.QueryRow(s.q(`SELECT body FROM submissions WHERE id = ?`), existingID).Scan(&body)
			if err == sql.ErrNoRows {
				return nil, false, fmt.Errorf("idempotency key %q points to missing submission", key)
			}
			if err != nil {
				return nil, false, err
			}
			var out api.Submission
			if err := json.Unmarshal([]byte(body), &out); err != nil {
				return nil, false, err
			}
			if err := tx.Commit(); err != nil {
				return nil, false, err
			}
			return &out, false, nil
		}
		if err != sql.ErrNoRows {
			return nil, false, err
		}
	}

	body, err := json.Marshal(sub)
	if err != nil {
		return nil, false, err
	}
	_, err = tx.Exec(s.q(`
		INSERT INTO submissions (id, body) VALUES (?, ?)
		ON CONFLICT(id) DO UPDATE SET body = excluded.body
	`), sub.ID, string(body))
	if err != nil {
		return nil, false, err
	}
	if key != "" {
		// INSERT; on conflict re-read as replay (handles concurrent same-key creates).
		res, err := tx.Exec(s.q(`
			INSERT INTO idempotency (key, submission_id, request_hash) VALUES (?, ?, ?)
			ON CONFLICT(key) DO NOTHING
		`), key, sub.ID, requestHash)
		if err != nil {
			return nil, false, err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			// Lost the race — load the winner and treat as replay.
			var existingID, existingHash string
			err := tx.QueryRow(s.q(`SELECT submission_id, request_hash FROM idempotency WHERE key = ?`), key).
				Scan(&existingID, &existingHash)
			if err != nil {
				return nil, false, err
			}
			if existingHash != "" && requestHash != "" && existingHash != requestHash {
				return nil, false, scintx.ErrIdempotencyConflict
			}
			// Drop our orphaned submission row.
			_, _ = tx.Exec(s.q(`DELETE FROM submissions WHERE id = ?`), sub.ID)
			var winBody string
			err = tx.QueryRow(s.q(`SELECT body FROM submissions WHERE id = ?`), existingID).Scan(&winBody)
			if err != nil {
				return nil, false, err
			}
			var out api.Submission
			if err := json.Unmarshal([]byte(winBody), &out); err != nil {
				return nil, false, err
			}
			if err := tx.Commit(); err != nil {
				return nil, false, err
			}
			return &out, false, nil
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	cp := api.CloneJSON(*sub)
	return &cp, true, nil
}

func (s *SQLStore) RememberIdempotencyKey(key, submissionID string) error {
	if key == "" {
		return nil
	}
	_, err := s.db.Exec(s.q(`
		INSERT INTO idempotency (key, submission_id, request_hash) VALUES (?, ?, '')
		ON CONFLICT(key) DO NOTHING
	`), key, submissionID)
	return err
}

func (s *SQLStore) AbandonSubmission(id, idempotencyKey string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var body string
	err = tx.QueryRow(s.q(`SELECT body FROM submissions WHERE id = ?`), id).Scan(&body)
	if err == sql.ErrNoRows {
		return scintx.ErrAbandonRejected
	}
	if err != nil {
		return err
	}
	var sub api.Submission
	if err := json.Unmarshal([]byte(body), &sub); err != nil {
		return err
	}
	if sub.Status != api.SubmissionAccepted {
		return scintx.ErrAbandonRejected
	}

	res, err := tx.Exec(s.q(`DELETE FROM submissions WHERE id = ?`), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return scintx.ErrAbandonRejected
	}
	if idempotencyKey != "" {
		if _, err := tx.Exec(s.q(`DELETE FROM idempotency WHERE key = ? AND submission_id = ?`), idempotencyKey, id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(s.q(`DELETE FROM jobs WHERE submission_id = ?`), id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) ClaimResume(id string) (*api.Submission, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	q := `SELECT body FROM submissions WHERE id = ?`
	if s.dialect == dialectPostgres {
		q = `SELECT body FROM submissions WHERE id = ? FOR UPDATE`
	}
	var body string
	err = tx.QueryRow(s.q(q), id).Scan(&body)
	if err == sql.ErrNoRows {
		return nil, scintx.ErrResumeNotDeferred
	}
	if err != nil {
		return nil, err
	}
	var sub api.Submission
	if err := json.Unmarshal([]byte(body), &sub); err != nil {
		return nil, err
	}
	if sub.Status != api.SubmissionDeferred {
		return nil, scintx.ErrResumeNotDeferred
	}
	sub.Status = api.SubmissionRunning
	raw, err := json.Marshal(sub)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(s.q(`UPDATE submissions SET body = ? WHERE id = ?`), string(raw), id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &sub, nil
}

func (s *SQLStore) ReleaseResume(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	q := `SELECT body FROM submissions WHERE id = ?`
	if s.dialect == dialectPostgres {
		q = `SELECT body FROM submissions WHERE id = ? FOR UPDATE`
	}
	var body string
	err = tx.QueryRow(s.q(q), id).Scan(&body)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	var sub api.Submission
	if err := json.Unmarshal([]byte(body), &sub); err != nil {
		return err
	}
	if sub.Status != api.SubmissionRunning {
		return nil
	}
	sub.Status = api.SubmissionDeferred
	reason := api.CompletionDeferred
	sub.CompletionReason = &reason
	sub.CompletedAt = nil
	raw, err := json.Marshal(sub)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(s.q(`UPDATE submissions SET body = ? WHERE id = ?`), string(raw), id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) GetSubmissionByIdempotencyKey(key string) (*api.Submission, bool, error) {
	if key == "" {
		return nil, false, nil
	}
	var id string
	err := s.db.QueryRow(s.q(`SELECT submission_id FROM idempotency WHERE key = ?`), key).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return s.GetSubmission(id)
}

func (s *SQLStore) PutResult(r *api.ProviderResult) error {
	if r == nil {
		return nil
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(s.q(`
		INSERT INTO results (id, submission_id, body) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET submission_id = excluded.submission_id, body = excluded.body
	`), r.ID, r.SubmissionID, string(body))
	return err
}

func (s *SQLStore) GetResult(id string) (*api.ProviderResult, bool, error) {
	var body string
	err := s.db.QueryRow(s.q(`SELECT body FROM results WHERE id = ?`), id).Scan(&body)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var r api.ProviderResult
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		return nil, false, err
	}
	return &r, true, nil
}

func (s *SQLStore) GetResultsForSubmission(subID string) ([]*api.ProviderResult, error) {
	rows, err := s.db.Query(s.q(`SELECT body FROM results WHERE submission_id = ?`), subID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*api.ProviderResult
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var r api.ProviderResult
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *SQLStore) PutMergedResult(r *api.MergedResult) error {
	if r == nil {
		return nil
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// One merged result per submission; upsert on submission_id.
	_, err = s.db.Exec(s.q(`
		INSERT INTO merged_results (submission_id, body) VALUES (?, ?)
		ON CONFLICT(submission_id) DO UPDATE SET body = excluded.body
	`), r.SubmissionID, string(body))
	return err
}

func (s *SQLStore) GetMergedResultForSubmission(subID string) (*api.MergedResult, bool, error) {
	var body string
	err := s.db.QueryRow(s.q(`SELECT body FROM merged_results WHERE submission_id = ?`), subID).Scan(&body)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var r api.MergedResult
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		return nil, false, err
	}
	return &r, true, nil
}

func (s *SQLStore) PutDecision(d *api.PolicyDecision) error {
	if d == nil {
		return nil
	}
	body, err := json.Marshal(d)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(s.q(`
		INSERT INTO decisions (id, body) VALUES (?, ?)
		ON CONFLICT(id) DO UPDATE SET body = excluded.body
	`), d.ID, string(body))
	return err
}

func (s *SQLStore) GetDecision(id string) (*api.PolicyDecision, bool, error) {
	var body string
	err := s.db.QueryRow(s.q(`SELECT body FROM decisions WHERE id = ?`), id).Scan(&body)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var d api.PolicyDecision
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		return nil, false, err
	}
	return &d, true, nil
}

func (s *SQLStore) AppendEvent(e api.CloudEvent) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(s.q(`INSERT INTO events (body) VALUES (?)`), string(body))
	return err
}

func (s *SQLStore) Events() ([]api.CloudEvent, error) {
	rows, err := s.db.Query(s.q(`SELECT body FROM events ORDER BY id ASC`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []api.CloudEvent
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var e api.CloudEvent
		if err := json.Unmarshal([]byte(body), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLStore) PutArtifact(digest string, content []byte) error {
	_, err := s.db.Exec(s.q(`
		INSERT INTO artifacts (digest, content) VALUES (?, ?)
		ON CONFLICT(digest) DO UPDATE SET content = excluded.content
	`), digest, content)
	return err
}

func (s *SQLStore) HasArtifact(digest string) (bool, error) {
	var n int
	err := s.db.QueryRow(s.q(`SELECT 1 FROM artifacts WHERE digest = ?`), digest).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *SQLStore) GetArtifact(digest string) ([]byte, bool, error) {
	var content []byte
	err := s.db.QueryRow(s.q(`SELECT content FROM artifacts WHERE digest = ?`), digest).Scan(&content)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	cp := make([]byte, len(content))
	copy(cp, content)
	return cp, true, nil
}

func (s *SQLStore) RegisterProvider(p scintx.ProviderEntry) error {
	body, err := json.Marshal(p.Capabilities)
	if err != nil {
		return err
	}
	var next int
	if err := s.db.QueryRow(s.q(`SELECT COALESCE(MAX(sort_order), 0) + 1 FROM providers`)).Scan(&next); err != nil {
		return err
	}
	_, err = s.db.Exec(s.q(`
		INSERT INTO providers (id, name, capabilities, sort_order)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			capabilities = excluded.capabilities
	`), p.ID, p.Name, string(body), next)
	return err
}

func (s *SQLStore) Providers() ([]scintx.ProviderEntry, error) {
	rows, err := s.db.Query(s.q(`SELECT id, name, capabilities FROM providers ORDER BY sort_order ASC, id ASC`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []scintx.ProviderEntry
	for rows.Next() {
		var e scintx.ProviderEntry
		var body string
		if err := rows.Scan(&e.ID, &e.Name, &body); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(body), &e.Capabilities); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetCapabilities(providerID string) (api.ProviderCapabilities, bool, error) {
	var body string
	err := s.db.QueryRow(s.q(`SELECT capabilities FROM providers WHERE id = ?`), providerID).Scan(&body)
	if err == sql.ErrNoRows {
		return api.ProviderCapabilities{}, false, nil
	}
	if err != nil {
		return api.ProviderCapabilities{}, false, err
	}
	var caps api.ProviderCapabilities
	if err := json.Unmarshal([]byte(body), &caps); err != nil {
		return api.ProviderCapabilities{}, false, err
	}
	return caps, true, nil
}

func (s *SQLStore) SnapshotCapabilities(providerID string, caps api.ProviderCapabilities) error {
	body, err := json.Marshal(caps)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(s.q(`UPDATE providers SET capabilities = ? WHERE id = ?`), string(body), providerID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("provider %q not registered", providerID)
	}
	return nil
}
