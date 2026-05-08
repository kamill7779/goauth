# GoAuth

GoAuth is a standalone, deployable identity service for new system scaffolds.

It is planned as a multi-tenant RBAC auth service with:

- Email-first registration and login.
- Access token and refresh token lifecycle management.
- OAuth2/OpenID Connect provider endpoints for downstream systems.
- External OAuth2 identity provider adapters, starting with GitHub.
- Redis-backed verification, rate limits, and permission/session caches.
- MySQL as the primary authoritative database.

## Documents

- [Design](docs/design.md)
- [Implementation Plan](docs/implementation-plan.md)
