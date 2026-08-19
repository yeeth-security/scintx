#!/usr/bin/env python3
"""Validate JSON Schema 2020-12 definitions against fixtures derived from the SCINTX e2e tests."""
import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

SCHEMA_DIR = Path("schema")
FAIL = 0
PASS = 0

def load_schema(name):
    with open(SCHEMA_DIR / name) as f:
        return json.load(f)

# Build a registry of all schemas by their $id
resources = []
for p in SCHEMA_DIR.glob("*.schema.json"):
    with open(p) as f:
        doc = json.load(f)
    resources.append((doc["$id"], Resource.from_contents(doc)))
registry = Registry().with_resources(resources)

def validate(schema_name, instance, label, should_fail=False):
    global FAIL, PASS
    schema = load_schema(schema_name)
    validator = Draft202012Validator(schema, registry=registry)
    errors = list(validator.iter_errors(instance))
    if should_fail:
        if errors:
            PASS += 1
            print(f"  PASS  {label} (correctly rejected)")
        else:
            FAIL += 1
            print(f"  FAIL  {label} (should have been rejected but wasn't)")
    else:
        if errors:
            FAIL += 1
            for e in errors:
                print(f"  FAIL  {label}: {e.message}")
                print(f"        path: {list(e.absolute_path)}")
        else:
            PASS += 1
            print(f"  PASS  {label}")

print("== SCINTX schema validation ==\n")

validate("resource-reference.schema.json", {
    "uri": "urn:scintx:blob:abc",
    "media_type": "application/json",
    "digests": {"sha256": "cd1988"},
    "format": "osv"
}, "resource-ref basic")

validate("artifact.schema.json", {"purl": "pkg:pypi/requests@2.32.3"}, "artifact purl-only")
validate("artifact.schema.json", {"digests": {"sha256": "abc"}}, "artifact digests-only")
validate("artifact.schema.json", {
    "content_ref": {"uri": "urn:scintx:blob:x", "media_type": "application/octet-stream"},
    "digests": {"sha256": "abc"}
}, "artifact content+digests")
validate("artifact.schema.json", {}, "artifact empty (should fail)", should_fail=True)

validate("submission-create.schema.json", {
    "schema_version": "1.0.0",
    "artifact": {"purl": "pkg:pypi/requests@2.32.3"},
    "requested_capabilities": ["vulnerability"],
    "policy_ref": "registry-default"
}, "submission-create purl")

validate("submission.schema.json", {
    "id": "sub_abc",
    "schema_version": "1.0.0",
    "artifact": {"purl": "pkg:pypi/requests@2.32.3"},
    "status": "completed",
    "completion_reason": "decision_produced",
    "created_at": "2026-08-17T14:12:03Z",
    "completed_at": "2026-08-17T14:14:04Z",
    "result_ids": ["res_1"],
    "decision_id": "dec_1"
}, "submission response completed")

validate("submission.schema.json", {
    "id": "sub_abc",
    "schema_version": "1.0.0",
    "artifact": {"purl": "pkg:npm/left-pad@1.3.0"},
    "status": "completed",
    "completion_reason": "findings_only",
    "created_at": "2026-08-17T14:12:03Z",
    "result_ids": ["res_1"],
    "decision_id": None
}, "submission findings-only (decision_id null)")

validate("provider-capabilities.schema.json", {
    "schema_version": "1.0.0",
    "provider": {"id": "stub-osv", "name": "stub-osv", "version": "2026.8"},
    "manifest_version": "1",
    "manifest_digest": "sha256:" + "a"*64,
    "updated_at": "2026-08-17T12:00:00Z",
    "capabilities": [{
        "id": "vulnerability",
        "version": "v1",
        "input_profiles": [{
            "id": "purl",
            "requires": [{"kind": "purl", "types": ["npm", "pypi"]}]
        }],
        "finding_types": ["vulnerability"]
    }]
}, "provider-capabilities basic")

validate("finding.schema.json", {
    "id": "OSV-2026-0001",
    "type": "vulnerability",
    "title": "SSRF via crafted redirect URL",
    "identifiers": [
        {"scheme": "OSV", "value": "OSV-2026-0001", "relation": "none"},
        {"scheme": "CVE", "value": "CVE-2026-12345", "relation": "alias"}
    ],
    "subjects": [{"purl": "pkg:pypi/requests@2.32.3"}],
    "subject_origin": "submitted_artifact",
    "severity": [{"scheme": "CVSS", "version": "4.0", "score": 8.7, "level": "high", "vector": "CVSS:4.0/...", "source": "provider"}],
    "weaknesses": [{"scheme": "CWE", "id": "CWE-918"}],
    "assessment": {"status": "affected"}
}, "finding with alias relation")

validate("finding.schema.json", {
    "id": "f1", "type": "vulnerability",
    "weaknesses": [{"scheme": "CWE", "id": "NOT-CWE"}]
}, "finding bad CWE (should fail)", should_fail=True)

validate("provider-result.schema.json", {
    "id": "res_1",
    "schema_version": "1.0.0",
    "submission_id": "sub_1",
    "provider": {"id": "stub-osv", "version": "2026.8"},
    "capabilities": ["vulnerability:v1"],
    "capability_manifest_digest": "sha256:" + "a"*64,
    "execution": {"status": "completed", "started_at": "2026-08-17T14:12:04Z", "finished_at": "2026-08-17T14:12:05Z"},
    "verdict": {"value": "pass", "origin": "provider"}
}, "result completed pass")

validate("provider-result.schema.json", {
    "id": "res_2",
    "schema_version": "1.0.0",
    "submission_id": "sub_1",
    "provider": {"id": "stub-osv", "version": "2026.8"},
    "capabilities": ["vulnerability:v1"],
    "capability_manifest_digest": "sha256:" + "a"*64,
    "execution": {"status": "completed", "started_at": "2026-08-17T14:12:04Z", "finished_at": "2026-08-17T14:12:05Z"},
    "verdict": {"value": "fail", "origin": "provider", "derivation": {"driven_by": [{"finding_id": "OSV-1", "weight": "primary"}], "summary": "1 finding"}},
    "findings": [{"id": "OSV-1", "type": "vulnerability", "assessment": {"status": "affected"}}]
}, "result completed fail with derivation")

validate("provider-result.schema.json", {
    "id": "res_3",
    "schema_version": "1.0.0",
    "submission_id": "sub_1",
    "provider": {"id": "stub-osv", "version": "2026.8"},
    "capabilities": ["vulnerability:v1"],
    "capability_manifest_digest": "sha256:" + "a"*64,
    "execution": {"status": "error", "started_at": "2026-08-17T14:12:04Z", "finished_at": "2026-08-17T14:12:05Z", "error": {"code": "transport_error", "message": "timeout"}},
    "verdict": {"value": "pass", "origin": "adapter"}
}, "result error with verdict (should fail)", should_fail=True)

validate("policy-decision.schema.json", {
    "id": "dec_1",
    "submission_id": "sub_1",
    "decision": "deny",
    "policy": {"id": "registry-default", "version": "1", "digest": "sha256:" + "b"*64},
    "evaluated_at": "2026-08-17T14:14:04Z",
    "input_result_ids": ["res_2"],
    "reasons": [{
        "code": "critical_severity_vulnerability",
        "result_id": "res_2",
        "finding_id": "OSV-1",
        "severity_ref": {"scheme": "CVSS", "version": "4.0", "score": 9.1},
        "message": "CVSS 9.1 vulnerability with no fix available"
    }]
}, "decision deny with finding reason")

validate("policy-decision.schema.json", {
    "id": "dec_2",
    "submission_id": "sub_1",
    "decision": "defer",
    "policy": {"id": "registry-default", "version": "1"},
    "evaluated_at": "2026-08-17T14:14:04Z",
    "input_result_ids": ["res_3"],
    "reasons": [{"code": "required_provider_timeout", "result_id": "res_3", "message": "Provider timed out"}],
    "resume_at": "2026-08-17T15:14:04Z",
    "resume_on": "org.eclipse.scintx.submission.resume"
}, "decision defer with resume_at")

validate("event.schema.json", {
    "specversion": "1.0",
    "id": "evt_1",
    "source": "https://scintx.example",
    "type": "org.eclipse.scintx.policy-decision.created.v1",
    "subject": "sub_1",
    "time": "2026-08-17T14:14:04Z",
    "data": {"decision": "deny", "decision_id": "dec_1"}
}, "cloudevent policy-decision.created")

validate("event.schema.json", {
    "specversion": "1.0",
    "id": "evt_resolved",
    "source": "https://scintx.example",
    "type": "org.eclipse.scintx.policy-decision.resolved.v1",
    "subject": "sub_1",
    "time": "2026-08-17T14:14:04Z",
    "data": {
        "decision": "allow",
        "decision_id": "dec_2",
        "prior_decision_id": "dec_1",
        "source": "registry-ui"
    }
}, "cloudevent policy-decision.resolved")

validate("adjudicate-request.schema.json", {
    "decision": "allow",
    "actor": "alice@example.com",
    "source": "registry-ui",
    "rationale": "Accepted risk until lodash>=4.17.21"
}, "adjudicate allow from consumer")

validate("adjudicate-request.schema.json", {
    "decision": "review"
}, "adjudicate review not allowed (should fail)", should_fail=True)

validate("event.schema.json", {
    "specversion": "1.0",
    "id": "evt_2",
    "source": "https://scintx.example",
    "type": "org.eclipse.scintx.unknown.event.v1",
    "time": "2026-08-17T14:14:04Z"
}, "cloudevent bad type (should fail)", should_fail=True)

validate("problem-details.schema.json", {
    "type": "https://scintx.example/problems/not_found",
    "title": "Not Found",
    "status": 404,
    "detail": "submission not found"
}, "problem-details basic")

validate("compatibility-result.schema.json", {
    "provider_id": "stub-osv",
    "capability": "malware:v1",
    "eligible": False,
    "reasons": [{"code": "missing_required_input", "input": "content"}]
}, "compatibility-result ineligible")

print(f"\n{PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)
print("All schema validations complete")