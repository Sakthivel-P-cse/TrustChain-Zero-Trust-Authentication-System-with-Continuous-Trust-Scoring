package dev.trustchain.application;

import dev.trustchain.domain.model.ServiceIdentity;
import dev.trustchain.domain.model.AuditEvent;
import dev.trustchain.domain.port.AuditLogger;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public final class ServiceTokenService {
    private final ServiceIdentitySource identities;
    private final ServiceTokenCodec codec;
    private final TokenReplayStore replayStore;
    private final Duration ttl;
    private final AuditLogger audit;

    public ServiceTokenService(ServiceIdentitySource identities, ServiceTokenCodec codec,
                               TokenReplayStore replayStore, Duration ttl) {
        this(identities, codec, replayStore, ttl, new AuditLogger() {
            @Override
            public void log(AuditEvent event) {
            }

            @Override
            public java.util.List<AuditEvent> findRecent(int limit) {
                return java.util.List.of();
            }
        });
    }

    public ServiceTokenService(ServiceIdentitySource identities, ServiceTokenCodec codec,
                               TokenReplayStore replayStore, Duration ttl, AuditLogger audit) {
        this.identities = identities;
        this.codec = codec;
        this.replayStore = replayStore;
        this.ttl = ttl;
        this.audit = audit;
    }

    public IssuedServiceToken issue(TokenCommand command, String certificateFingerprint) {
        ServiceIdentityRecord requesting = identities.find(command.requestingServiceId())
                .orElseThrow(() -> denied(command, "service_not_found"));
        if (!requesting.identity().certificateFingerprint().equals(certificateFingerprint)) {
            throw denied(command, "client_certificate_mismatch");
        }
        if (!requesting.identity().tenantId().equals(command.delegatedTenantId())) {
            throw denied(command, "cross_tenant_impersonation_denied");
        }
        if (!requesting.allowedActions().contains(command.scopedAction())) {
            throw denied(command, "action_not_allowed");
        }
        String jti = UUID.randomUUID().toString();
        Instant expiresAt = Instant.now().plus(ttl);
        Map<String, Object> claims = Map.of(
                "jti", jti,
                "requestingServiceId", command.requestingServiceId(),
                "targetServiceId", command.targetServiceId(),
                "delegatedUserId", command.delegatedUserId(),
                "delegatedTenantId", command.delegatedTenantId(),
                "scopedAction", command.scopedAction());
        IssuedServiceToken issued = new IssuedServiceToken(codec.encode(claims, ttl), expiresAt);
        log(command.requestingServiceId(), command.delegatedTenantId(), command.delegatedUserId(),
                command.scopedAction(), command.targetServiceId(), "allowed", "service_token_issued");
        return issued;
    }

    public ValidatedServiceToken validateAndConsume(String token, String targetServiceId, String action) {
        DecodedServiceToken decoded;
        try {
            decoded = codec.decode(token);
        } catch (RuntimeException exception) {
            auditBoundaryDenial("service_token_invalid");
            throw exception;
        }
        ServiceIdentityRecord activeIdentity = identities.find(decoded.requestingServiceId()).orElse(null);
        if (activeIdentity == null || !activeIdentity.identity().tenantId().equals(decoded.delegatedTenantId())) {
            log(decoded.requestingServiceId(), decoded.delegatedTenantId(), decoded.delegatedUserId(),
                    action, targetServiceId, "denied", "service_tenant_inactive");
            throw new ServiceTokenException("service_tenant_inactive");
        }
        if (decoded.expiresAt().isBefore(Instant.now())) {
            log(decoded.requestingServiceId(), decoded.delegatedTenantId(), decoded.delegatedUserId(),
                    decoded.scopedAction(), targetServiceId, "denied", "service_token_expired");
            throw new ServiceTokenException("service_token_expired");
        }
        if (!decoded.targetServiceId().equals(targetServiceId) || !decoded.scopedAction().equals(action)) {
            log(decoded.requestingServiceId(), decoded.delegatedTenantId(), decoded.delegatedUserId(),
                    action, targetServiceId, "denied", "action_not_in_scope");
            throw new ServiceTokenException("action_not_in_scope");
        }
        Duration remaining = Duration.between(Instant.now(), decoded.expiresAt());
        if (remaining.isNegative() || remaining.isZero() || !replayStore.markUsed(decoded.jti(), remaining)) {
            log(decoded.requestingServiceId(), decoded.delegatedTenantId(), decoded.delegatedUserId(),
                    action, targetServiceId, "denied", "service_token_reused");
            throw new ServiceTokenException("service_token_reused");
        }
        log(decoded.requestingServiceId(), decoded.delegatedTenantId(), decoded.delegatedUserId(),
                action, targetServiceId, "allowed", "service_token_consumed");
        return new ValidatedServiceToken(decoded.requestingServiceId(), decoded.delegatedUserId(),
                decoded.delegatedTenantId(), decoded.scopedAction());
    }

    public interface ServiceIdentitySource {
        Optional<ServiceIdentityRecord> find(String serviceId);
    }

    public interface ServiceTokenCodec {
        String encode(Map<String, Object> claims, Duration ttl);

        DecodedServiceToken decode(String token);
    }

    @FunctionalInterface
    public interface TokenReplayStore {
        boolean markUsed(String jti, Duration ttl);
    }

    public record ServiceIdentityRecord(ServiceIdentity identity, Set<String> allowedActions) {
        public ServiceIdentityRecord {
            allowedActions = Set.copyOf(allowedActions);
        }
    }

    public record TokenCommand(String requestingServiceId, String targetServiceId, String delegatedUserId,
                               String delegatedTenantId, String scopedAction) {
    }

    public record IssuedServiceToken(String token, Instant expiresAt) {
    }

    public record DecodedServiceToken(String jti, String requestingServiceId, String targetServiceId,
                                      String delegatedUserId, String delegatedTenantId, String scopedAction,
                                      Instant expiresAt) {
    }

    public record ValidatedServiceToken(String serviceId, String delegatedUserId, String delegatedTenantId,
                                        String scopedAction) {
    }

    public static final class ServiceTokenException extends RuntimeException {
        public ServiceTokenException(String message) {
            super(message);
        }
    }

    public void auditBoundaryDenial(String reason) {
        log("unknown-service", null, null, "service-token", "service-token", "denied", reason);
    }

    private ServiceTokenException denied(TokenCommand command, String reason) {
        log(command.requestingServiceId(), command.delegatedTenantId(), command.delegatedUserId(),
                command.scopedAction(), command.targetServiceId(), "denied", reason);
        return new ServiceTokenException(reason);
    }

    private void log(String serviceId, String tenantId, String userId, String action, String resource,
                     String outcome, String reason) {
        audit.log(new AuditEvent(UUID.randomUUID().toString(), serviceId, tenantId, userId, action, resource,
                outcome, reason, Instant.now()));
    }
}
