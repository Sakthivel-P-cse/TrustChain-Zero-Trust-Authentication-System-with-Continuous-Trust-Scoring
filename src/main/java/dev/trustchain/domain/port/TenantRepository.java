package dev.trustchain.domain.port;

import dev.trustchain.domain.model.Tenant;

import java.util.List;
import java.util.Optional;

public interface TenantRepository {
    void save(Tenant tenant);

    Optional<Tenant> findById(String id);

    List<Tenant> findAllActive();

    void markInactive(String id);
}
