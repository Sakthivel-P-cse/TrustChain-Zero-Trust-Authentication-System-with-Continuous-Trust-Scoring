package dev.trustchain.web;

import dev.trustchain.application.TenantProvisioningService;
import dev.trustchain.domain.model.AuditEvent;
import dev.trustchain.domain.model.Tenant;
import dev.trustchain.domain.port.AuditLogger;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;
import java.util.Map;
import java.time.Instant;
import java.util.UUID;

@RestController
@RequestMapping("/admin")
public final class TenantAdminController {
    private final TenantProvisioningService provisioning;
    private final AuditLogger audit;

    public TenantAdminController(TenantProvisioningService provisioning, AuditLogger audit) {
        this.provisioning = provisioning;
        this.audit = audit;
    }

    @PostMapping("/tenants")
    public Tenant provision(@RequestBody Map<String, String> request) {
        Tenant tenant = provisioning.provisionTenant(request.get("name"));
        log(tenant.id(), "tenant_provision", "allowed", "tenant_provisioned");
        return tenant;
    }

    @DeleteMapping("/tenants/{tenantId}")
    public Map<String, String> deprovision(@PathVariable String tenantId) {
        provisioning.deprovisionTenant(tenantId);
        log(tenantId, "tenant_deprovision", "allowed", "schema_retained");
        return Map.of("status", "inactive", "retention", "schema_preserved");
    }

    @GetMapping("/audit")
    public List<AuditEvent> audit(@RequestParam(defaultValue = "20") int limit) {
        return audit.findRecent(Math.min(100, Math.max(1, limit)));
    }

    private void log(String tenantId, String action, String outcome, String reason) {
        String userId = null;
        if (SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken jwt) {
            userId = jwt.getToken().getClaimAsString("userId");
        }
        audit.log(new AuditEvent(UUID.randomUUID().toString(), null, tenantId, userId, action, "tenant",
                outcome, reason, Instant.now()));
    }
}
