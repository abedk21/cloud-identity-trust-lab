"""Fail-closed policy evaluation of pre-verified *synthetic* claims.

This is not an OIDC validator, token verifier, Security Token Service, CEL engine,
or Google Cloud IAM implementation. It cannot authenticate an identity.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    binding: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _valid_resource(resource: object) -> bool:
    if not isinstance(resource, str) or not resource or resource.startswith('/'):
        return False
    if '%' in resource or '\\' in resource or '//' in resource:
        return False
    return all(segment not in ('', '.', '..') for segment in resource.split('/'))


def _resource_matches(rule: str, resource: str) -> bool:
    if rule == '*' or rule.count('*') > (1 if rule.endswith('/*') else 0) or not _valid_resource(rule.replace('/*', '/item')):
        return False
    if rule.endswith('/*'):
        prefix = rule[:-2]
        return resource.startswith(prefix + '/')
    return rule == resource


def lint_policy(policy: dict[str, Any]) -> list[str]:
    """Return deterministic configuration errors; all errors prevent authorization."""
    errors: list[str] = []
    for key in ('issuer', 'audience'):
        if not isinstance(policy.get(key), str) or not policy[key].strip():
            errors.append(f'missing_{key}')
    for key in ('allowed_org_ids', 'allowed_repositories', 'allowed_refs'):
        val = policy.get(key)
        if not isinstance(val, list) or not val or not all(isinstance(x, str) and x and x != '*' for x in val):
            errors.append(f'invalid_{key}')
    max_age = policy.get('max_token_age_seconds')
    if type(max_age) is not int or not 0 < max_age <= 86400:
        errors.append('invalid_max_age')
    permissions = policy.get('permissions')
    if not isinstance(permissions, dict) or not permissions:
        errors.append('invalid_permissions')
        permissions = {}
    for role, statements in permissions.items():
        if not isinstance(statements, list) or not statements:
            errors.append(f'invalid_statements:{role}')
            continue
        for i, stmt in enumerate(statements):
            if not isinstance(stmt, dict) or not isinstance(stmt.get('resource'), str) or stmt['resource'] == '*' or stmt['resource'].count('*') > (1 if stmt['resource'].endswith('/*') else 0) or not _valid_resource(stmt['resource'].replace('/*', '/item')):
                errors.append(f'invalid_resource_rule:{role}:{i}')
            actions = stmt.get('actions') if isinstance(stmt, dict) else None
            if not isinstance(actions, list) or not actions or '*' in actions or not all(isinstance(a, str) and a for a in actions):
                errors.append(f'invalid_actions:{role}:{i}')
    bindings = policy.get('bindings')
    if not isinstance(bindings, list) or not bindings:
        errors.append('invalid_bindings')
        bindings = []
    seen: set[str] = set()
    for i, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            errors.append(f'invalid_binding:{i}')
            continue
        name = binding.get('name')
        if not isinstance(name, str) or not name or name in seen:
            errors.append(f'invalid_binding_name:{i}')
        else:
            seen.add(name)
        for field in ('role', 'repository', 'ref', 'environment'):
            if not isinstance(binding.get(field), str) or not binding[field] or binding[field] == '*':
                errors.append(f'invalid_binding_{field}:{i}')
        if binding.get('role') not in permissions:
            errors.append(f'undefined_role:{i}')
    return sorted(set(errors))


def authorize(policy: dict[str, Any], claims: dict[str, Any], request: dict[str, Any], *, now: int) -> Decision:
    """Evaluate *pre-verified* mock claims; never use output for real authorization."""
    if lint_policy(policy):
        return Decision(False, 'INVALID_POLICY')
    if type(now) is not int:
        return Decision(False, 'INVALID_TIME')
    if not isinstance(claims, dict) or not isinstance(request, dict):
        return Decision(False, 'INVALID_INPUT')
    if claims.get('iss') != policy['issuer']:
        return Decision(False, 'ISSUER_MISMATCH')
    aud = claims.get('aud')
    audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
    if policy['audience'] not in audiences or not all(isinstance(x, str) for x in audiences):
        return Decision(False, 'AUDIENCE_MISMATCH')
    iat, exp, nbf = claims.get('iat'), claims.get('exp'), claims.get('nbf', claims.get('iat'))
    if any(type(x) is not int for x in (iat, exp, nbf)):
        return Decision(False, 'INVALID_TIMESTAMP')
    if exp <= now:
        return Decision(False, 'EXPIRED')
    if iat > now + 60 or nbf > now + 60:
        return Decision(False, 'NOT_YET_VALID')
    if iat > exp or nbf > exp or now - iat > policy['max_token_age_seconds']:
        return Decision(False, 'INVALID_TOKEN_AGE')
    if claims.get('repository_owner_id') not in policy['allowed_org_ids']:
        return Decision(False, 'ORG_NOT_ALLOWED')
    repo, ref, env = claims.get('repository'), claims.get('ref'), claims.get('environment')
    if repo not in policy['allowed_repositories']:
        return Decision(False, 'REPOSITORY_NOT_ALLOWED')
    if ref not in policy['allowed_refs']:
        return Decision(False, 'REF_NOT_ALLOWED')
    if not all(isinstance(x, str) for x in (repo, ref, env)):
        return Decision(False, 'MISSING_WORKLOAD_ATTRIBUTES')
    if claims.get('sub') != f'repo:{repo}:ref:{ref}':
        return Decision(False, 'SUBJECT_BINDING_MISMATCH')
    resource, action = request.get('resource'), request.get('action')
    if not _valid_resource(resource) or not isinstance(action, str) or not action:
        return Decision(False, 'INVALID_RESOURCE_OR_ACTION')
    for binding in policy['bindings']:
        if (binding['repository'], binding['ref'], binding['environment']) != (repo, ref, env):
            continue
        for statement in policy['permissions'][binding['role']]:
            if action in statement['actions'] and _resource_matches(statement['resource'], resource):
                return Decision(True, 'PERMITTED', binding['name'])
    return Decision(False, 'NO_MATCHING_BINDING')
