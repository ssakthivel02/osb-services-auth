# Authentication Production Readiness

Status: **NO-GO until every mandatory gate has objective evidence.**

## Identity provider

- Production issuer selected and ownership recorded.
- Exact redirect URIs registered; wildcard redirects prohibited.
- Authorisation Code with PKCE enabled.
- OIDC discovery and JWKS endpoints reachable through TLS.
- Issuer and audience values pinned per environment.
- Test, staging and production tenants are isolated.

## Cryptography and keys

- Signing keys are asymmetric and held in managed key storage.
- Private signing keys never enter source control, logs or application configuration.
- JWKS publishes current and overlap keys with unique key IDs.
- Planned rotation has been rehearsed.
- Emergency compromise rotation has been rehearsed.
- Unknown, expired, revoked and wrong-algorithm keys are rejected.

## Tokens and sessions

- Access tokens expire within 15 minutes.
- Refresh tokens rotate on every use.
- Refresh-token family is revoked on reuse.
- Issuer, audience, expiry, issued-at, subject, JTI and tenant claims are enforced.
- Clock skew is bounded.
- Logout and global session revocation are tested.
- Browser cookies use Secure, HttpOnly and an appropriate SameSite mode.

## Authorisation and tenant isolation

- Tenant context comes only from verified identity claims or trusted server-side mapping.
- Request parameters and headers cannot override tenant identity.
- Default-deny RBAC is implemented.
- Privileged roles require MFA.
- Separation-of-duties conflicts are enforced.
- Guardian-child relationships are verified and auditable.
- Cross-tenant negative tests pass at API and persistence layers.

## Abuse resistance

- Login, recovery, token and introspection endpoints are rate limited.
- Credential-stuffing and password-spraying alerts are enabled.
- Lockout avoids account-enumeration leakage.
- Recovery responses are indistinguishable for existing and unknown accounts.
- CAPTCHA or equivalent step-up control is available for abnormal traffic.

## Operations and evidence

- Authentication health and readiness probes are defined.
- Audit events exclude credentials and raw tokens.
- Security alerts have named owners and escalation paths.
- Severity-one response is tested.
- Backup and restore are tested for token/session state where applicable.
- Recovery-time and recovery-point objectives are approved.
- Privacy, retention and deletion controls cover authentication records.

## Release evidence

Attach evidence for each mandatory gate: CI run, configuration export, test result, screenshot, audit extract or approved change record. A statement without evidence does not satisfy a gate.
