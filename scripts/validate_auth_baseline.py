#!/usr/bin/env python3
"""Validate the OSB authentication security baseline without third-party packages."""
from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(path: str) -> dict[str, Any]:
    with (ROOT / path).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_policy(policy: dict[str, Any]) -> None:
    require(policy.get("issuer", "").startswith("https://"), "issuer must use HTTPS")
    require(60 <= policy.get("accessTokenTtlSeconds", 0) <= 900, "access-token TTL must be 60-900 seconds")
    require(policy.get("refreshTokenTtlSeconds", 0) <= 2_592_000, "refresh-token TTL must not exceed 30 days")
    require(policy.get("clockSkewSeconds", 999) <= 120, "clock skew must not exceed 120 seconds")
    allowed = set(policy.get("allowedAlgorithms", []))
    require(bool(allowed), "at least one signing algorithm is required")
    require(allowed <= {"RS256", "ES256"}, "only RS256 or ES256 are permitted")
    require("none" in policy.get("disallowedAlgorithms", []), "unsigned tokens must be prohibited")
    for flag in ("requirePkce", "requireState", "rotateRefreshTokens", "revokeRefreshTokenFamilyOnReuse"):
        require(policy.get(flag) is True, f"{flag} must be enabled")
    required_claims = set(policy.get("requiredClaims", []))
    require({"iss", "aud", "sub", "exp", "iat", "jti", "tenant_id"} <= required_claims,
            "required token claims are incomplete")
    require(policy.get("minimumPasswordLength", 0) >= 14, "minimum password length must be at least 14")
    require(policy.get("requireMfaForPrivilegedRoles") is True, "MFA is required for privileged roles")
    require(policy.get("maximumFailedAttempts", 99) <= 5, "failed-attempt threshold must be five or fewer")


def validate_roles(data: dict[str, Any]) -> None:
    roles = data.get("roles")
    require(isinstance(roles, dict) and roles, "roles must be a non-empty object")
    require("platform_admin" in roles and "learner" in roles, "required platform and learner roles are missing")
    for role, permissions in roles.items():
        require(isinstance(permissions, list) and permissions, f"role {role} has no permissions")
        require(len(permissions) == len(set(permissions)), f"role {role} contains duplicate permissions")
        require(all(isinstance(item, str) and ":" in item for item in permissions),
                f"role {role} has malformed permissions")
    tenant_scoped = set(data.get("tenantScopedRoles", []))
    require(tenant_scoped <= set(roles), "tenantScopedRoles references undefined roles")
    for pair in data.get("separationOfDuties", []):
        require(isinstance(pair, list) and len(pair) == 2, "separation-of-duties entries must be role pairs")
        require(set(pair) <= set(roles), "separation-of-duties pair references undefined role")


def main() -> int:
    try:
        validate_policy(load("config/auth-policy.json"))
        validate_roles(load("config/roles.json"))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"AUTH BASELINE INVALID: {exc}", file=sys.stderr)
        return 1
    print("AUTH BASELINE VALID")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
