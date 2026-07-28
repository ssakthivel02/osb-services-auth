# Authentication Threat Model

## Scope

Identity-provider integration, authorisation code flow, token validation, session management, tenant claims, role assignment, privileged administration and audit events.

## Trust boundaries

1. User agent to edge/API gateway.
2. API gateway to authentication service.
3. Authentication service to identity provider and key store.
4. Service to tenant-aware data platform.
5. Administrative interfaces to privileged control plane.

## Principal threats and controls

| Threat | Required control | Evidence |
|---|---|---|
| Stolen authorisation code | PKCE, state and exact redirect URI matching | Policy validation and integration test |
| Token substitution | Issuer, audience, algorithm and signature validation | Negative token tests |
| Replay | `jti`, short TTL, nonce where applicable and refresh rotation | Replay/reuse test |
| Algorithm downgrade | Explicit RS256/ES256 allow-list; reject `none` and HMAC | Baseline validator |
| Cross-tenant access | Verified `tenant_id` claim propagated to RLS context | Negative isolation test |
| Privilege escalation | Server-side RBAC, separation of duties and MFA | Role-policy test and audit evidence |
| Session fixation | Regenerate session after authentication and privilege change | Session integration test |
| Credential stuffing | Rate limit, lockout, telemetry and risk response | Abuse-control test |
| Key compromise | Managed keys, rotation, versioned JWKS and emergency revocation | Rotation drill |
| Sensitive logging | Redaction; never log tokens, secrets or passwords | Log scanning test |
| Open redirect | Registered exact redirect URIs only | Negative redirect test |
| CSRF | State validation and secure same-site cookies where used | Negative state test |

## Child and guardian context

Guardian linkage, child consent and role assignment must be verified server-side. A guardian cannot self-assert a child relationship or expand access by changing request fields. Child-related audit and privacy events must avoid unnecessary personal data.

## Residual risk gates

Production remains NO-GO until an external identity provider is selected, redirect URIs are registered, keys are stored in a managed key service, negative token tests execute against a running service, rate limits are proven, and a key-rotation/revocation drill is recorded.
