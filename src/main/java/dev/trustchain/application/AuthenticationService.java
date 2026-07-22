package dev.trustchain.application;

import dev.trustchain.domain.model.Session;
import dev.trustchain.domain.model.User;
import dev.trustchain.domain.port.UserRepository;
import dev.trustchain.domain.port.TenantRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;
import java.util.function.Supplier;

public final class AuthenticationService {
    private final UserRepository users;
    private final TenantRepository tenants;
    private final SessionService sessions;
    private final PasswordVerifier passwordVerifier;
    private final TokenIssuer tokenIssuer;
    private final TenantScope tenantScope;
    private final Duration accessTokenTtl;
    private final Duration refreshTokenTtl;

    public AuthenticationService(UserRepository users, TenantRepository tenants, SessionService sessions, PasswordVerifier passwordVerifier,
                                 TokenIssuer tokenIssuer, TenantScope tenantScope, Duration accessTokenTtl,
                                 Duration refreshTokenTtl) {
        this.users = users;
        this.tenants = tenants;
        this.sessions = sessions;
        this.passwordVerifier = passwordVerifier;
        this.tokenIssuer = tokenIssuer;
        this.tenantScope = tenantScope;
        this.accessTokenTtl = accessTokenTtl;
        this.refreshTokenTtl = refreshTokenTtl;
    }

    public AuthenticationResult authenticate(String tenantId, String email, String password, String remoteAddress) {
        tenants.findById(tenantId).orElseThrow(() -> new IllegalArgumentException("tenant_inactive"));
        User user = tenantScope.withTenant(tenantId, () -> users.findByEmail(email)
                .filter(found -> found.tenantId().equals(tenantId))
                .orElseThrow(() -> new IllegalArgumentException("invalid_credentials")));
        String passwordHash = tenantScope.withTenant(tenantId, () -> users.findPasswordHash(user.id())
                .orElseThrow(() -> new IllegalArgumentException("invalid_credentials")));
        if (!passwordVerifier.matches(password, passwordHash)) {
            throw new IllegalArgumentException("invalid_credentials");
        }
        Instant now = Instant.now();
        Session session = new Session(UUID.randomUUID().toString(), user.id(), tenantId, remoteAddress, now, now, true);
        sessions.create(session);
        Map<String, Object> claims = new HashMap<>();
        claims.put("tenantId", tenantId);
        claims.put("sessionId", session.id());
        claims.put("userId", user.id());
        claims.put("roles", user.roles().stream().map(role -> role.name()).sorted().toList());
        return new AuthenticationResult(tokenIssuer.issue(claims, accessTokenTtl, false),
                tokenIssuer.issue(claims, refreshTokenTtl, true), accessTokenTtl.toSeconds());
    }

    @FunctionalInterface
    public interface PasswordVerifier {
        boolean matches(String rawPassword, String encodedPassword);
    }

    @FunctionalInterface
    public interface TenantScope {
        <T> T withTenant(String tenantId, Supplier<T> operation);
    }

    @FunctionalInterface
    public interface TokenIssuer {
        String issue(Map<String, Object> claims, Duration ttl, boolean refreshToken);
    }

    public record AuthenticationResult(String accessToken, String refreshToken, long expiresIn) {
    }
}
