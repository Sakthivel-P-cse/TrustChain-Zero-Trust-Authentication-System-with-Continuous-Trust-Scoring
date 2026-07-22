package dev.trustchain.application;

import dev.trustchain.domain.model.AuditEvent;
import dev.trustchain.domain.model.Permission;
import dev.trustchain.domain.model.TrustScore;
import dev.trustchain.domain.model.User;
import dev.trustchain.domain.policy.AbacEvaluator;
import dev.trustchain.domain.policy.RbacEvaluator;
import dev.trustchain.domain.policy.TrustSignalProvider;
import dev.trustchain.domain.port.AuditLogger;
import dev.trustchain.domain.port.UserRepository;
import dev.trustchain.domain.port.TenantRepository;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.List;

public final class AuthorizationService {
    private final SessionService sessions;
    private final UserRepository users;
    private final TenantRepository tenants;
    private final RbacEvaluator rbac;
    private final AbacEvaluator abac;
    private final AuditLogger audit;
    private final AbacPolicySource abacPolicies;

    public AuthorizationService(SessionService sessions, UserRepository users, TenantRepository tenants,
                                RbacEvaluator rbac, AbacEvaluator abac, AuditLogger audit,
                                AbacPolicySource abacPolicies) {
        this.sessions = sessions;
        this.users = users;
        this.tenants = tenants;
        this.rbac = rbac;
        this.abac = abac;
        this.audit = audit;
        this.abacPolicies = abacPolicies;
    }

    public AuthorizationDecision authorize(AuthorizationRequest request) {
        if (tenants.findById(request.tenantId()).isEmpty()) {
            sessions.terminate(request.sessionId());
            return deny(request, 401, "tenant_inactive", 0);
        }
        SessionService.SessionState state = sessions.find(request.sessionId()).orElse(null);
        if (state == null || !state.session().active() || !state.session().tenantId().equals(request.tenantId())) {
            return deny(request, 401, "session_invalid", state == null ? 0 : state.score().score());
        }
        if (state.score().isTerminated()) {
            sessions.terminate(request.sessionId());
            return deny(request, 401, "trust_score_exhausted", state.score().score());
        }
        User user = users.findById(request.userId()).filter(found -> found.tenantId().equals(request.tenantId())).orElse(null);
        if (user == null) {
            return deny(request, 403, "user_not_in_tenant", state.score().score());
        }
        if (!rbac.evaluate(user, new Permission(request.resource(), request.action()))) {
            Map<String, String> attributes = new HashMap<>(request.attributes());
            attributes.put("permissionDenied", "true");
            TrustScore score = evaluate(request, attributes);
            return deny(request, 403, "rbac_denied", score.score());
        }
        AbacEvaluator.AbacDecision abacDecision = abac.evaluate(user,
                new AbacEvaluator.Resource(request.ownerTenantId(), request.sensitivityLevel(), Map.of()),
                request.attributes(), abacPolicies.rules(request.tenantId()));
        if (!abacDecision.allowed()) {
            return deny(request, 403, abacDecision.reason(), state.score().score());
        }
        TrustScore score = evaluate(request, request.attributes());
        if (score.isTerminated()) {
            sessions.terminate(request.sessionId());
            return deny(request, 401, "trust_score_exhausted", score.score());
        }
        if (score.isReadOnly() && isMutating(request.method())) {
            return deny(request, 403, "trust_score_insufficient", score.score());
        }
        log(request, "allowed", "policy_passed");
        return new AuthorizationDecision(true, 200, "allowed", score.score());
    }

    private TrustScore evaluate(AuthorizationRequest request, Map<String, String> attributes) {
        return sessions.evaluate(request.sessionId(), new TrustSignalProvider.HttpRequest(request.remoteAddress(),
                request.method(), Instant.now(), attributes));
    }

    private AuthorizationDecision deny(AuthorizationRequest request, int status, String reason, int score) {
        log(request, "denied", reason);
        return new AuthorizationDecision(false, status, reason, score);
    }

    private void log(AuthorizationRequest request, String outcome, String reason) {
        audit.log(new AuditEvent(UUID.randomUUID().toString(), request.sessionId(), request.tenantId(),
                request.userId(), request.action(), request.resource(), outcome, reason, Instant.now()));
    }

    private boolean isMutating(String method) {
        return method.equals("POST") || method.equals("PUT") || method.equals("PATCH") || method.equals("DELETE");
    }

    public record AuthorizationRequest(String sessionId, String tenantId, String userId, String method,
                                       String resource, String action, String remoteAddress, String ownerTenantId,
                                       int sensitivityLevel, Map<String, String> attributes) {
        public AuthorizationRequest {
            attributes = Map.copyOf(attributes);
        }
    }

    public record AuthorizationDecision(boolean allowed, int status, String reason, int trustScore) {
    }

    @FunctionalInterface
    public interface AbacPolicySource {
        List<AbacEvaluator.Rule> rules(String tenantId);
    }
}
