# Cloud Identity Trust Lab

[![Tests](https://github.com/abedk21/cloud-identity-trust-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/abedk21/cloud-identity-trust-lab/actions/workflows/tests.yml)

An **offline trust-policy decision simulator** that illustrates scoped workload federation, subject binding, organization restrictions, expiry checks, least-privilege roles, and auditable allow/deny reasons. Designed as a security engineering portfolio lab with synthetic claims, no secrets, and no external traffic.

## Quick start

```bash
python -m pip install -e .
python -m cloud_identity.cli lint
python -m cloud_identity.cli evaluate
python -m cloud_identity.cli scenarios
python -m unittest discover -s tests -v
```

Expected sample result: `PERMITTED`, by the `ci-artifact-reader` binding.

## Architecture

Synthetic claims + requested action/resource → issuer/audience/time checks → organization/repository/ref/subject binding → least-privilege authorization → structured decision.

| Check | What the lab shows |
|---|---|
| Issuer & audience | Exact-match allow lists, including exact membership in an audience list |
| Expiry & issued-at | Bounded credentials and rejects for expired/future/old claims |
| Trust boundary | Immutable organization ID, repository, branch and subject consistency checks |
| Privilege | Role bindings limited to environment, action and resource prefix |
| Auditability | Structured decisions without emitting a token or sensitive claim values |
| Validation | Fail-closed rejection of invalid policy configuration and path traversal |

## Non-goals and honest limits

**This tool does not authenticate anyone.** The claims are plain JSON that an attacker could forge if submitted directly. There is **no JWT signature verification, OIDC discovery, exchange with STS, GCP IAM API integration, CEL interpreter, or service-account impersonation**. In real systems, a trusted, cryptographically verified token exchange and IAM enforcement is required before authorization. Do not use this simulator as a security control.

The rules are deliberately simplified and are **not** a complete implementation of Google Cloud Workload Identity Federation. Google Cloud documentation notes the importance of stable subject mappings and attribute conditions for multi-tenant issuers.

Reference: [Google Cloud WIF overview](https://docs.cloud.google.com/iam/docs/workload-identity-federation) · [WIF best practices](https://docs.cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation)

## Test and demo

- `fixtures/policy.json` defines example trust constraints and scoped roles.
- `fixtures/sample_case.json` defines one authorized synthetic workload request.
- `fixtures/scenarios.json` contains nine allow/deny cases with expected reason codes.
- `tests/test_identity.py` covers spoofed subject/issuer/audience, old tokens, resource escape, branch collisions, policy misconfiguration, and role scope.
- GitHub Actions runs `unittest` without installing third-party dependencies.

The `example.invalid` URL is intentionally non-resolvable. All values are fictional.
