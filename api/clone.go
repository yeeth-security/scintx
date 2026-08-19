package api

import "encoding/json"

// CloneJSON deep-copies v via JSON round-trip.
// Used by the in-memory store so HTTP handlers never share mutable pointers
// with background workers (avoids data races on Submission status fields).
func CloneJSON[T any](v T) T {
	b, err := json.Marshal(v)
	if err != nil {
		var zero T
		return zero
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		var zero T
		return zero
	}
	return out
}
