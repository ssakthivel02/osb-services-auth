# Security Policy

## Supported baseline

The supported security baseline is the latest commit on `main`. Backport support must be declared explicitly for any release branch.

## Private reporting

Do not disclose suspected vulnerabilities in public issues. Report them privately to the repository owner with impact, safe reproduction steps, affected components and non-sensitive evidence. Never include live credentials, access tokens, refresh tokens, signing keys or personal data.

## Mandatory controls

- Secrets and signing keys are supplied by the deployment platform and never committed.
- Access tokens are short-lived, issuer-bound and audience-restricted.
- Refresh tokens are rotated; detected reuse revokes the token family.
- Privileged roles require MFA.
- Tenant identity comes from verified authentication claims, never a free-form request field.
- Algorithm, issuer, audience, expiry, issued-at, subject, token ID and tenant claims are validated.
- Authentication and privilege events generate audit records without token bodies or secrets.
- Material architecture deviations require an ADR and security review.

## Severity-one conditions

Signing-key compromise, refresh-token reuse, authentication bypass, privilege escalation and cross-tenant access are severity-one events. Revoke affected credentials, rotate keys, preserve evidence, identify impacted tenants and complete an authorised recovery decision before restoring normal operation.

## Review cadence

Review this policy at least every six months and after any significant authentication, identity-provider, cryptographic or tenant-isolation change.
