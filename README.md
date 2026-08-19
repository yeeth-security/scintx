# SCINTX

> **S**upply **C**hain **INT**elligence E**X**change — a vendor-neutral open
> standard for package-security integration.

SCINTX sits between package registries and security providers, defining a
common submission API, normalized verdict vocabulary, policy engine, and signed
webhook lifecycle. The goal is to eliminate duplicated integration work, make
security verdicts portable, and let registries and enterprises mix-and-match
providers without vendor lock-in.

Proposed for contribution to the Eclipse Foundation as
**Eclipse Supply Chain Gateway**. A project of
[Yeeth Security](https://github.com/yeeth-security).

---

## Why

Security providers produce heterogeneous information — different schemas,
different verdict vocabularies, different notions of severity and confidence.
Meanwhile, registries and organizations need a portable way to consume that
information and apply policy across it. Today every registry builds bespoke
integrations with individual vendors, with no shared data model and no
portability: a verdict from one provider cannot be compared with, substituted
for, or combined with a verdict from another.

SCINTX breaks that pattern by defining a vendor-neutral integration layer —
normalizing provider output into a common verdict model and giving registries
and organizations a single policy surface that works across any conforming
provider. A verdict becomes portable, a policy becomes auditable, and a
registry can swap or mix providers without rewriting its integration.

---

## Scope

**Core**

- An interoperability specification for package-security scanning, normalized
  verdict/security model, provider interface, and policy model.
- A reference implementation of the gateway and policy engine.
- Reference adapters for major security providers.
- HTTP integration for registries, CI, and feed bridges (e.g. package-feeds).

**Out of scope**

- Operating a public package registry.
- In-process registry pollers (prefer external feeds → `POST /v1/submissions`).
- Replacing existing security scanners — SCINTX *integrates* scanners, it does
  not compete with them.
- Commercial hosting or SaaS offerings — those may be offered independently by
  ecosystem vendors.

---

## Quickstart

Requires [Go 1.25+](https://go.dev/dl/).

```bash
git clone https://github.com/yeeth-security/scintx.git
cd scintx
make build
./bin/scintx
```

The gateway listens on `:8080`. With no `SCINTX_STORE` set it runs as an
ephemeral forwarder (in-memory; state is gone on restart).

Submit a package URL:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/submissions \
  -H 'Content-Type: application/json' \
  -d '{
    "schema_version": "1.0.0",
    "artifact": {"purl": "pkg:npm/left-pad@1.3.0"},
    "requested_capabilities": ["vulnerability"],
    "policy_ref": "registry-default"
  }'
```

Poll `GET /v1/submissions/{id}` until `status` is `completed`, then
`GET /v1/submissions/{id}/results` (and `/merged` when several providers ran).

**Live providers.** Default load is every registered factory. For OSV + Sonatype
OSS Index:

```bash
./bin/scintx auth ossindex          # Guide PAT → OS keyring (not .env)
SCINTX_PROVIDERS=osv,ossindex ./bin/scintx
```

Create a Guide PAT at https://guide.sonatype.com. CI should inject
`SCINTX_OSSINDEX_TOKEN` from a secret store instead of `auth`.

Useful targets: `make run`, `make test`, `make check`. Full env list:
[`.env.example`](.env.example).

---

## License

Distributed under the Eclipse Public License 2.0 (EPL-2.0).

Changes: [CHANGELOG.md](CHANGELOG.md).

---

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the reference gateway
design (ASD-STE100 style, with diagrams). Extensions:
[docs/EXTENSIONS.md](docs/EXTENSIONS.md).

A project of [Yeeth Security](https://github.com/yeeth-security).