# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ProviderResult.raw_results[]` — first-class multi-report companion artifacts
  (native tool JSON, SARIF, future SBOM/attestation). Discriminated by
  `format` / `media_type` on each `ResourceReference`.
- `api.AttachRawReport` — hash + append a report and stash bytes for the
  orchestrator to persist via `PutArtifact`.
- Per-provider SARIF 2.1.0 companion reports in `raw_results` (native→SARIF
  convert in each adapter, or tool passthrough where available).
- OSV provider: `vscode-extension` PURL support with ecosystem fallback when
  PURL-only queries miss (e.g. Open VSX malware indexed as
  `VSCode:https://open-vsx.org` / `publisher.name`).
- `SCINTX_MAX_ARTIFACT_BYTES` — configurable `POST /v1/artifacts` body cap
  (default 1 GiB); over-limit returns `413 artifact_too_large`.
- Reference HTTP gateway (`scintx serve`) with worker pool, optional YAML policy, and CloudEvent webhooks.
- In-memory store by default (ephemeral forwarder). Optional durable `sqlite` / `postgres`.
- Live providers: OSV.dev (`osv`) and Sonatype OSS Index (`ossindex`).
- Offline stubs (`stub-osv`, `stub-secrets`) for tests and demos.
- Cross-provider finding merge (CVE-anchored) and `GET /v1/submissions/{id}/merged`.
- `scintx auth <provider>` — OS keyring (file fallback) for outbound provider credentials.
- Optional anonymous adjudication forwarding (`SCINTX_FORWARD_ADJUDICATIONS`, off by default).
- Artifact blob upload (`POST /v1/artifacts`) and hydration of local blob bytes onto `Artifact.Content` before `Assess` (not sent to PURL APIs).
- JSON Schema 2020-12 documents, OpenAPI 3.1, and README quickstart.
- CI (`make check`) and GitHub Actions workflows.
- EPL-2.0 license.

### Removed

- `ProviderResult.raw_result` (singular). Use `raw_results` only. Pre-release
  breaking change — no compatibility alias.

### Changed

- Artifact upload limit raised from 32 MiB to 1 GiB (override via `SCINTX_MAX_ARTIFACT_BYTES`).
- Artifact read failures now include the underlying error detail; size breaches
  use problem title `artifact_too_large` instead of a generic 400.

[Unreleased]: https://github.com/yeeth-security/scintx/commits/HEAD
