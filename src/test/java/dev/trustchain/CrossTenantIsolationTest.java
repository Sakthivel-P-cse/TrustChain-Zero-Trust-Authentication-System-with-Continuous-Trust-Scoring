package dev.trustchain;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.trustchain.domain.model.User;
import dev.trustchain.infrastructure.persistence.JdbcUserRepository;
import dev.trustchain.infrastructure.persistence.TenantSchemaRouter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.Statement;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers(disabledWithoutDocker = true)
class CrossTenantIsolationTest {
    @Container
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine");
    static TenantSchemaRouter router;
    static JdbcUserRepository users;

    @BeforeAll
    static void provisionSchemas() throws Exception {
        PGSimpleDataSource dataSource = new PGSimpleDataSource();
        dataSource.setURL(postgres.getJdbcUrl());
        dataSource.setUser(postgres.getUsername());
        dataSource.setPassword(postgres.getPassword());
        router = new TenantSchemaRouter(dataSource);
        users = new JdbcUserRepository(router, new ObjectMapper());
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            createTenant(statement, "tenant_org_a");
            createTenant(statement, "tenant_org_b");
        }
        router.withTenant("org-a", () -> {
            users.save(new User("user-a", "org-a", "a@test", Set.of(), Map.of()), "hash");
            return null;
        });
        router.withTenant("org-b", () -> {
            users.save(new User("user-b", "org-b", "b@test", Set.of(), Map.of()), "hash");
            return null;
        });
    }

    @Test
    void tenantASearchPathCannotSeeTenantBUser() {
        assertThat(router.withTenant("org-a", () -> users.findById("user-b"))).isEmpty();
        assertThat(router.withTenant("org-a", () -> users.findById("user-a"))).isPresent();
    }

    private static void createTenant(Statement statement, String schema) throws Exception {
        statement.execute("CREATE SCHEMA " + schema);
        statement.execute("CREATE TABLE " + schema + ".users (id VARCHAR(36) PRIMARY KEY, tenant_id VARCHAR(36), email VARCHAR(255), password_hash VARCHAR(100), attributes JSONB)");
        statement.execute("CREATE TABLE " + schema + ".roles (name VARCHAR(100) PRIMARY KEY)");
        statement.execute("CREATE TABLE " + schema + ".permissions (role_name VARCHAR(100), resource VARCHAR(100), action VARCHAR(100))");
        statement.execute("CREATE TABLE " + schema + ".role_assignments (user_id VARCHAR(36), role_name VARCHAR(100))");
    }
}
