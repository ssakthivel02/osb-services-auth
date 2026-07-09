# API Specification

## Endpoints
- POST /v1/login
- POST /v1/refresh
- POST /v1/introspect
- GET /v1/jwks

## Security
JWT RS256, refresh-token rotation, OPA-backed authorization, Redis-backed rate limiting.
