# Architecture - osb-services-auth

## Overview
Authentication, identity, RBAC, OIDC/OAuth2 and zero trust access. This repository is part of the OmSaravanaBhava Learning Ecosystem Enterprise Architecture v1.0.

## Context diagram
```mermaid
graph TD
    User[User / Service] --> Repo[osb-services-auth]
    Repo --> Standards[osb-engineering-standards]
    Repo --> Platform[osb-platform-foundation]
```

## Architecture principles
- Secure by default
- Observable by default
- API-first where applicable
- Documentation-as-code
- ADR-controlled change

## Dependencies
See `ROADMAP.md` for implementation sequence and dependency notes.
