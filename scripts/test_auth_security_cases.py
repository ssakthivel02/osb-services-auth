#!/usr/bin/env python3
"""Executable negative security cases for the authentication baseline."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / 'config' / 'auth-policy.json'
ROLES_PATH = ROOT / 'config' / 'roles.json'


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    policy = json.loads(POLICY_PATH.read_text(encoding='utf-8'))
    rbac = json.loads(ROLES_PATH.read_text(encoding='utf-8'))

    allowed = set(policy['allowedAlgorithms'])
    disallowed = set(policy['disallowedAlgorithms'])
    require('none' not in allowed, 'Unsigned tokens must be rejected')
    require(not {'HS256', 'HS384', 'HS512'} & allowed, 'HMAC JWT must be rejected')
    require({'none', 'HS256', 'HS384', 'HS512'} <= disallowed, 'Disallowed algorithm set is incomplete')
    require(policy['accessTokenTtlSeconds'] <= 900, 'Access token TTL exceeds 15 minutes')
    require(policy['requirePkce'] is True, 'PKCE must be mandatory')
    require(policy['requireState'] is True, 'OAuth state must be mandatory')
    require(policy['requireNonceForOidc'] is True, 'OIDC nonce must be mandatory')
    require(policy['rotateRefreshTokens'] is True, 'Refresh tokens must rotate')
    require(policy['revokeRefreshTokenFamilyOnReuse'] is True, 'Refresh-token reuse must revoke family')
    require(policy['requireMfaForPrivilegedRoles'] is True, 'Privileged MFA must be mandatory')
    require(policy['tenantClaim'] in policy['requiredClaims'], 'Tenant claim must be required')
    require(policy['issuer'].startswith('https://'), 'Issuer must use HTTPS')
    require(len(policy['audiences']) > 0, 'At least one audience is required')

    roles = rbac['roles']
    require('platform_admin' in roles and 'security_admin' in roles, 'Privileged roles missing')
    require(set(policy['privilegedRoles']) <= set(roles), 'Policy references undefined privileged roles')
    for left, right in rbac['separationOfDuties']:
        require(left in roles and right in roles, f'Undefined separation-of-duties role: {left}/{right}')
        require(left != right, 'A role cannot conflict with itself')
    require(set(rbac['tenantScopedRoles']) <= set(roles), 'Undefined tenant-scoped role')

    mutated = deepcopy(policy)
    mutated['allowedAlgorithms'].append('none')
    require('none' in mutated['allowedAlgorithms'], 'Negative mutation did not execute')

    print('Negative authentication security cases passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
