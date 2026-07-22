# TrustChain

TrustChain is a zero-trust authentication and authorization service that combines short-lived JWT identity with continuous, per-session trust evaluation. Standard OAuth2/JWT systems largely treat a valid token as sufficient until expiry; TrustChain reevaluates behavior on every protected request, independently requires RBAC and ABAC approval, physically scopes database access to a tenant schema, and automatically downgrades or terminates anomalous sessions.

## Architecture

```text
Client ──> Auth server ──> signed user JWT
  │             │
  │             ├──> PostgreSQL public schema ──> tenants, services, audit
  │             ├──> PostgreSQL tenant schema ──> users, roles, ABAC rules
  │             └──> Redis ──> sessions, trust scores, replay protection
  │
  └── JWT ──> authorization + trust filters ──> downstream API/service
                         │
                         └── RBAC ∩ ABAC ∩ trust threshold
```

## Run

Java 21 and Gradle 8 are required. Copy `.env.example`, replace both signing secrets with private values, export them, and enable the loopback-only demo certificate adapter before starting:

```bash
export JWT_SECRET='replace-with-at-least-32-random-bytes'
export SERVICE_JWT_SECRET='replace-with-another-32-random-bytes'
export TRUSTCHAIN_DEMO_ENABLED=true
docker-compose up -d
./gradlew bootRun
```

In another terminal:

```bash
./scripts/run_demo.sh
```

The repository intentionally follows the requested exact file inventory, which excludes Gradle wrapper files. If your checkout does not already supply `gradlew`, run `gradle bootRun` with Gradle 8.

Demo credentials are `user-a@orga.test` / `password` and `user-b@orgb.test` / `password`. `X-Forwarded-For` and the certificate fingerprint header are accepted only from loopback while explicit demo mode is enabled. Production mode requires the verified client `X509Certificate` supplied by the TLS session, hashes it with SHA-256, and rejects requests without a client certificate.

## Trust score

| Signal | Delta |
|---|---:|
| IP address change | -15 |
| Impossible travel over 500 km | -40 |
| Request rate over 3× session average | -20 |
| More than 3 denied permissions in 10 minutes | -25 |

A fresh authentication starts at 100. Scores from 70 through 100 have full access, scores from 40 through 69 are read-only, and scores below 40 terminate the session. Positive recovery without fresh authentication is capped at 80. This prevents score-farming, where an attacker slowly restores a compromised session to maximum trust without proving identity again.

## Risk model

| Fully closed | Meaningfully reduced | Open and documented |
|---|---|---|
| Cross-tenant data access through structural schema isolation | Session hijacking through behavioral trust decay | Trust signals are heuristic rather than ML-based and can produce false positives |
| Session continuation after trust exhaustion | Privilege escalation because RBAC and ABAC must pass independently | GeoIP is a mock lookup; production impossible-travel detection needs a real provider |
| Service-token replay through single-use JTI enforcement |  | mTLS certificate rotation is out of scope |
| Cross-tenant service impersonation |  | Schema-per-tenant needs sharding beyond roughly 1,000 tenants |

## Known limitations

- Behavioral signals are transparent heuristics, so unusual legitimate behavior can reduce trust.
- Impossible-travel locations use a small mock IP table; production needs a maintained GeoIP source and uncertainty handling.
- Certificate enrollment and rotation are deployment concerns and are not implemented by this service.
- PostgreSQL schema-per-tenant isolation trades operational simplicity at small scale for catalog pressure at large scale; shard before approximately 1,000 tenants.
- Tenant deprovisioning marks the tenant inactive but intentionally retains its schema to satisfy data-retention policy.
