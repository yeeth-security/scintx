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
- Reference adapters for major package registries and security providers.

**Out of scope**

- Operating a public package registry.
- Replacing existing security scanners — SCINTX *integrates* scanners, it does
  not compete with them.
- Commercial hosting or SaaS offerings — those may be offered independently by
  ecosystem vendors.

---

## License

Distributed under the Eclipse Public License 2.0 (EPL-2.0).

---

A project of [Yeeth Security](https://github.com/yeeth-security).