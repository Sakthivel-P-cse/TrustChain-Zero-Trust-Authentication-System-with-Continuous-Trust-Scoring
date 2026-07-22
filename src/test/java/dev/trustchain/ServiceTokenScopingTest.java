package dev.trustchain;

import dev.trustchain.application.ServiceTokenService;
import dev.trustchain.domain.model.ServiceIdentity;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ServiceTokenScopingTest {
    private final ServiceTokenService.ServiceIdentitySource identities = serviceId -> java.util.Optional.of(
            new ServiceTokenService.ServiceIdentityRecord(
                    new ServiceIdentity("order-service", "org-a", "fingerprint"),
                    Set.of("read:orders", "write:orders")));

    @Test
    void crossTenantDelegationIsRejectedAtIssuance() {
        ServiceTokenService service = service(Duration.ofSeconds(60));
        assertThatThrownBy(() -> service.issue(command("org-b", "read:orders"), "fingerprint"))
                .hasMessage("cross_tenant_impersonation_denied");
    }

    @Test
    void actionOutsideServiceAllowListIsRejected() {
        ServiceTokenService service = service(Duration.ofSeconds(60));
        assertThatThrownBy(() -> service.issue(command("org-a", "write:payments"), "fingerprint"))
                .hasMessage("action_not_allowed");
    }

    @Test
    void serviceTokenCanOnlyBeUsedOnce() {
        ServiceTokenService service = service(Duration.ofSeconds(60));
        String token = service.issue(command("org-a", "read:orders"), "fingerprint").token();
        service.validateAndConsume(token, "payment-service", "read:orders");
        assertThatThrownBy(() -> service.validateAndConsume(token, "payment-service", "read:orders"))
                .hasMessage("service_token_reused");
    }

    @Test
    void expiredServiceTokenIsRejected() {
        ServiceTokenService service = service(Duration.ofSeconds(-1));
        String token = service.issue(command("org-a", "read:orders"), "fingerprint").token();
        assertThatThrownBy(() -> service.validateAndConsume(token, "payment-service", "read:orders"))
                .hasMessage("service_token_expired");
    }

    private ServiceTokenService service(Duration ttl) {
        MemoryCodec codec = new MemoryCodec();
        Set<String> used = new HashSet<>();
        return new ServiceTokenService(identities, codec, (jti, ignored) -> used.add(jti), ttl);
    }

    private ServiceTokenService.TokenCommand command(String tenantId, String action) {
        return new ServiceTokenService.TokenCommand("order-service", "payment-service", "user-a", tenantId, action);
    }

    private static final class MemoryCodec implements ServiceTokenService.ServiceTokenCodec {
        private final Map<String, ServiceTokenService.DecodedServiceToken> tokens = new HashMap<>();

        @Override
        public String encode(Map<String, Object> claims, Duration ttl) {
            String token = UUID.randomUUID().toString();
            tokens.put(token, new ServiceTokenService.DecodedServiceToken(claims.get("jti").toString(),
                    claims.get("requestingServiceId").toString(), claims.get("targetServiceId").toString(),
                    claims.get("delegatedUserId").toString(), claims.get("delegatedTenantId").toString(),
                    claims.get("scopedAction").toString(), Instant.now().plus(ttl)));
            return token;
        }

        @Override
        public ServiceTokenService.DecodedServiceToken decode(String token) {
            return tokens.get(token);
        }
    }
}
