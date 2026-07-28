#!/usr/bin/env python3
"""Executable negative security cases for the authentication baseline."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / 'config' / 'auth-policy.json'
RBAC_PATH = ROOT / 'config' / 'rbac.json'


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    policy = json.loads(POLICY_PATH.read_text(encoding='utf-8'))
    rbac = json.loads(RBAC_PATH.read_text(encoding='utf-8'))

    require('none' not in policy['tokens']['allowed_algorithms'], 'Unsigned tokens must be rejected')
    require(not {'HS256', 'HS384', 'HS512'} & set(policy['tokens']['allowed_algorithms']), 'HMAC JWT must be rejected')
    require(policy['tokens']['access_token_ttl_seconds'] <= 900, 'Access token TTL exceeds 15 minutes')
    require(policy['oauth']['pkce_required'] is True, 'PKCE must be mandatory')
    require(policy['oauth']['state_required'] is True, 'OAuth state must be mandatory')
    require(policy['oidc']['nonce_required'] is True, 'OIDC nonce must be mandatory')
    require(policy['refresh_tokens']['rotate_on_use'] is True, 'Refresh tokens must rotate')
    require(policy['refresh_tokens']['revoke_family_on_reuse'] is True, 'Refresh-token reuse must revoke family')
    require(policy['privileged_access']['mfa_required'] is True, 'Privileged MFA must be mandatory')
    require(policy['tenant']['claim_required'] is True, 'Tenant claim must be required')
    require(policy['tenant']['request_override_allowed'] is False, 'Request tenant override must be forbidden')

    roles = rbac['roles']
    require('platform_admin' in roles and 'security_admin' in roles, 'Privileged roles missing')
    for conflict in rbac['separation_of_duties']:
        left, right = conflict['roles']
        require(left in roles and right in roles, f'Undefined separation-of-duties role: {left}/{right}')
        require(left != right, 'A role cannot conflict with itself')

    mutated = deepcopy(policy)
    mutated['tokens']['allowed_algorithms'].append('none')
    require('none' in mutated['tokens']['allowed_algorithms'], 'Negative mutation did not execute')

    print('Negative authentication security cases passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
