# ADR 0001: Token and session security baseline

- Status: Accepted
- Date: 2026-07-28

## Context

OSB services require tenant-aware authentication across web, mobile and service APIs. Long-lived bearer tokens, symmetric shared secrets and request-supplied tenant identifiers would create unacceptable replay, key-distribution and cross-tenant risks.

## Decision

Use OAuth 2.1-style authorisation code flow with PKCE for public clients and OpenID Connect where identity claims are required. Access tokens are asymmetric JWTs signed with RS256 or ES256, expire within 15 minutes, and are validated for signature, algorithm, issuer, audience, subject, expiry, issued-at, token ID and tenant claim. Refresh tokens are rotated, and reuse revokes the token family. Privileged roles require MFA. Tenant context is derived only from verified claims and propagated to downstream row-level security inside a transaction.

Browser sessions should prefer secure, HTTP-only, same-site cookies rather than exposing tokens to JavaScript. Exact redirect URIs, state and nonce validation are mandatory where applicable.

## Consequences

A managed identity provider and key service are required. Consumers must support JWKS refresh and key overlap during rotation. Revocation storage and security telemetry become production dependencies. Integration tests must cover invalid signatures, issuer/audience mismatch, expired/future tokens, replay, refresh reuse, role escalation and cross-tenant denial.

## Rejected alternatives

- Unsigned tokens: no authenticity.
- HS256 shared secrets across services: broad compromise blast radius and poor key separation.
- Long-lived access tokens: excessive replay window.
- Tenant ID from headers or request bodies without claim verification: enables tenant spoofing.
