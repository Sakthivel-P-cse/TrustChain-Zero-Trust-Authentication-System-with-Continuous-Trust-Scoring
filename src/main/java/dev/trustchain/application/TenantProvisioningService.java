package dev.trustchain.application;

import dev.trustchain.domain.model.Tenant;
import dev.trustchain.domain.port.TenantRepository;

import java.util.UUID;

public final class TenantProvisioningService {
    private final TenantRepository tenants;
    private final TenantSchemaManager schemas;

    public TenantProvisioningService(TenantRepository tenants, TenantSchemaManager schemas) {
        this.tenants = tenants;
        this.schemas = schemas;
    }

    public Tenant provisionTenant(String name) {
        String id = UUID.randomUUID().toString();
        Tenant tenant = new Tenant(id, name, "tenant_" + id.replace('-', '_'));
        tenants.save(tenant);
        schemas.createAndSeed(tenant, null);
        return tenant;
    }

    public void deprovisionTenant(String tenantId) {
        tenants.markInactive(tenantId);
    }

    public void seedDemoTenants() {
        tenants.findAllActive().forEach(tenant -> {
            String userId = tenant.id().equals("org-a") ? "user-a" : "user-b";
            String email = tenant.id().equals("org-a") ? "user-a@orga.test" : "user-b@orgb.test";
            schemas.createAndSeed(tenant, new SeedUser(userId, email, "password"));
        });
    }

    @FunctionalInterface
    public interface TenantSchemaManager {
        void createAndSeed(Tenant tenant, SeedUser user);
    }

    public record SeedUser(String id, String email, String password) {
    }
}
