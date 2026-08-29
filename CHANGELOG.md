# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once tagged releases exist.

## [Unreleased]

### Added

- OSV provider: `vscode-extension` PURL support with ecosystem fallback when
  PURL-only queries miss (e.g. Open VSX malware indexed as
  `VSCode:https://open-vsx.org` / `publisher.name`).
- Reference HTTP gateway (`scintx serve`) with worker pool, optional YAML policy, and CloudEvent webhooks.
- In-memory store by default (ephemeral **forwarder**). Optional durable `sqlite` / `postgres`.
- Live providers: OSV.dev (`osv`) and Sonatype OSS Index (`ossindex`).
- Offline stubs (`stub-osv`, `stub-secrets`) for tests and demos.
- Cross-provider finding merge (CVE-anchored) and `GET /v1/submissions/{id}/merged`.
- `scintx auth <provider>` — OS keyring (file fallback) for outbound provider credentials.
- Optional anonymous adjudication forwarding (`SCINTX_FORWARD_ADJUDICATIONS`, off by default).
- Artifact blob upload (`POST /v1/artifacts`) and hydration of local blob bytes onto `Artifact.Content` before `Assess` (not sent to PURL APIs).
- JSON Schema 2020-12 documents, OpenAPI 3.1, README quickstart.
- CI (`make check`) and GitHub Actions.

### Changed

- Extension registry uses `init()` + `go generate` (`extensions/*/all`).
- Public contract lives in `api/`; providers must not import `internal/`.

### Security

- GitHub Actions pinned to commit SHAs, `permissions: contents: read`, `persist-credentials: false`.
- Schema Python dependencies installed with `--require-hashes`.
- Dependabot for Actions and pip (`scripts/`).

## [0.0.1] — 2026-08-16

### Added

- Initial public repository: EPL-2.0 license and project README.
