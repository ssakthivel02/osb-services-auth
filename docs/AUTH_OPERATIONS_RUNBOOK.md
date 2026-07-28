# Authentication Operations Runbook

## Health and readiness

A production service must expose separate liveness and readiness checks. Readiness fails when signing-key metadata, identity-provider discovery, required persistence or revocation dependencies are unavailable. Health responses must not disclose secrets, internal endpoints or user data.

## Key rotation

1. Generate a new asymmetric key in the managed key service.
2. Publish the new public key with a unique `kid` before signing with it.
3. Verify all consumers refresh JWKS successfully.
4. Begin signing new tokens with the new key.
5. Retain the previous public key until every token signed by it has expired plus clock skew.
6. Remove the retired public key and preserve rotation evidence.

Emergency compromise response skips the overlap period where necessary and revokes affected sessions and refresh-token families.

## Refresh-token reuse

On detected reuse: reject the request, revoke the entire token family, terminate related sessions, record a high-severity audit event, notify the affected user through an approved channel and investigate possible credential theft.

## Tenant-context failure

Reject requests lacking a valid tenant claim when the operation is tenant-scoped. Never substitute a default tenant. For cross-tenant evidence, disable the affected route or service, preserve logs and correlation IDs, revoke implicated sessions and follow severity-one incident handling.

## Privileged access

Privileged role changes require MFA, an authorised administrator, separation-of-duties checks and an immutable audit event. Emergency access must be time-bound, independently reviewed and revoked after use.

## Monitoring signals

Alert on signature failures, invalid issuer/audience, repeated token reuse, lockout spikes, abnormal privilege changes, MFA bypass attempts, cross-tenant denials, unusual refresh rates and key-discovery failures.

## Recovery evidence

Record timestamps, affected tenants, key IDs, revoked session counts, commands or deployment references, validation results, approver and residual risks. Never paste raw tokens or secrets into evidence records.
