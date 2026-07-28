# Authentication Observability Standard

## Required signals

### Availability and latency
- Authorisation, token, refresh, logout, recovery and JWKS request counts.
- Success, client-error and server-error rates by endpoint.
- p50, p95 and p99 latency.
- Dependency latency and failure rate for identity provider, key store, database and cache.

### Security
- Failed logins by account hash, tenant, source network and device risk class.
- Lockouts, MFA challenges, MFA failures and recovery attempts.
- Refresh-token reuse and token-family revocation.
- Invalid issuer, audience, signature, algorithm, expiry, nonce, state and PKCE events.
- Unknown key ID and stale JWKS cache events.
- Privileged-role grants, removals and emergency-access activation.
- Tenant-claim mismatch and cross-tenant denial events.

### Capacity and resilience
- Active sessions and refresh-token families.
- Token issuance throughput.
- Cache hit ratio and eviction rate.
- Connection pool saturation.
- Queue depth and retry volume.
- Key-rotation overlap state.

## Logging rules

Never log passwords, authorisation codes, raw access tokens, refresh tokens, session cookies, private keys, client secrets or MFA seeds. Record correlation ID, timestamp, outcome, reason code, tenant-safe identifier, actor-safe identifier, client identifier and source-risk metadata.

## Alerting minimums

- Severity 1: signing-key compromise, confirmed authentication bypass, confirmed cross-tenant access or mass account takeover.
- Severity 2: refresh-token reuse spike, sustained token endpoint failures, JWKS outage or privileged-role anomaly.
- Severity 3: elevated login failures, latency SLO breach or dependency degradation.

Alerts must be deduplicated, routed to a named owner and linked to the authentication operations runbook.

## Service objectives

Before production, owners must approve measurable objectives for availability, token endpoint latency, recovery time and security-event response. Error budgets must exclude planned tests only when formally recorded.

## Evidence

Dashboards, alert rules, sample sanitised events and an exercised alert-to-runbook path are mandatory release evidence.
