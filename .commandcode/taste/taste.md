# Taste (Continuously Learned by [CommandCode][cmd])

[cmd]: https://commandcode.ai/

# code-style
- Use Java records for immutable value types instead of Lombok or MapStruct. Confidence: 0.85
- Zero comments except a single line above a non-obvious function where the name alone is insufficient; no Javadoc, no block comments, no TODO stubs. Confidence: 0.85
- SOLID throughout: one responsibility per class, depend on interfaces not implementations, all dependencies injected via constructor. Confidence: 0.85
- Enforce loose coupling via ports-and-adapters (hexagonal) architecture: domain logic must never import Spring, JDBC, or Redis directly. Confidence: 0.85
- Generate only files required to run the system, pass essential tests, or execute the demo; no placeholder classes, no "future use" packages. Confidence: 0.85

# architecture
- Use schema-per-tenant PostgreSQL isolation where the DB search_path makes cross-tenant data access physically impossible at the connection level. Confidence: 0.70
- Use signal providers (TrustSignalProvider interface) for pluggable behavioral anomaly detection that returns deltas, with the evaluator only orchestrating providers. Confidence: 0.70

# testing
- Use Testcontainers with real PostgreSQL and Redis in integration tests, no mocks for the data layer. Confidence: 0.70
- Test only security-critical logic: trust score computation, RBAC/ABAC evaluation, cross-tenant isolation, and service-token scoping; everything else verified by the demo script. Confidence: 0.70

# spring-boot
- Use Spring Boot 3.3 with Java 21 virtual threads enabled (spring.threads.virtual.enabled=true). Confidence: 0.75
- Configure JWT resource server for API endpoints; session management set to STATELESS with CSRF disabled. Confidence: 0.75
- Use Flyway for database migrations with the spring.flyway.enabled=true configuration. Confidence: 0.70
