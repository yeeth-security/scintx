package scintx

import (
	"fmt"

	"github.com/yeeth-security/scintx/api"
)

// hydrateLocalBlob copies stored bytes onto artifact.Content when content_ref
// is a urn:scintx:blob:… URI. External URLs are left alone (Content stays nil).
// A local blob that is missing is an error: providers must not Assess empty.
func (o *Orchestrator) hydrateLocalBlob(artifact *api.Artifact) error {
	if artifact == nil || artifact.ContentRef == nil {
		return nil
	}
	digest, ok := api.LocalBlobDigest(artifact.ContentRef.URI)
	if !ok {
		return nil
	}
	body, found, err := o.store.GetArtifact(digest)
	if err != nil {
		return fmt.Errorf("load artifact %s: %w", digest, err)
	}
	if !found {
		return fmt.Errorf("local blob %s is missing from the store", digest)
	}
	artifact.Content = body
	return nil
}
