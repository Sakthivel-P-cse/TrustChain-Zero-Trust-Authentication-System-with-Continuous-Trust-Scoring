package dev.trustchain.infrastructure.persistence;

import dev.trustchain.domain.model.Tenant;
import dev.trustchain.domain.port.TenantRepository;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Optional;

public final class JdbcTenantRepository implements TenantRepository {
    private final JdbcTemplate jdbc;

    public JdbcTenantRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void save(Tenant tenant) {
        jdbc.update("INSERT INTO tenants(id, name, schema_name) VALUES (?, ?, ?)",
                tenant.id(), tenant.name(), tenant.schemaName());
    }

    @Override
    public Optional<Tenant> findById(String id) {
        return jdbc.query("SELECT id, name, schema_name FROM tenants WHERE id = ? AND active",
                (result, row) -> new Tenant(result.getString(1), result.getString(2), result.getString(3)), id)
                .stream().findFirst();
    }

    @Override
    public List<Tenant> findAllActive() {
        return jdbc.query("SELECT id, name, schema_name FROM tenants WHERE active ORDER BY id",
                (result, row) -> new Tenant(result.getString(1), result.getString(2), result.getString(3)));
    }

    @Override
    public void markInactive(String id) {
        jdbc.update("UPDATE tenants SET active = false WHERE id = ?", id);
    }
}
