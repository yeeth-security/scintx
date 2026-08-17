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

Software supply-chain attacks on public registries are accelerating, yet every
registry solves the same problem in isolation. Registries build bespoke
integrations with individual security vendors, with no shared data model and no
portability. There is no open standard for how a registry submits a package for
scanning, what shape a security verdict takes, or how policy is applied and
audited.

SCINTX breaks that pattern by defining a vendor-neutral integration layer — so
a verdict from one provider is portable, a policy is auditable, and a registry
can swap providers without rewriting its integration.

---

## Scope

**In scope**

- A vendor-neutral open specification for package-security scanning, verdict
  normalization, policy application, and webhook lifecycle.
- A reference implementation of the gateway, policy engine, review console, and
  provider/registry adapters.
- Reference adapters for major package registries and security providers.
- Conformance profiles and an open registry of conformant providers and adapters.

**Out of scope**

- Operating a public package registry.
- Replacing existing security scanners — SCINTX *integrates* scanners, it does
  not compete with them.
- Commercial hosting or SaaS offerings — those may be offered independently by
  ecosystem vendors.

---

## Governance

SCINTX is proposed for contribution to the Eclipse Foundation as
**Eclipse Supply Chain Gateway**, a vendor-neutral specification and
reference-implementation project governed under the Eclipse Foundation
Specification Process, with the Eclipse Foundation holding the project
trademark. Yeeth Security retains the **Open Gateway** product trademark as a
downstream compatible implementation.

---

## License

Distributed under the Eclipse Public License 2.0 (EPL-2.0).

---

A project of [Yeeth Security](https://github.com/yeeth-security).