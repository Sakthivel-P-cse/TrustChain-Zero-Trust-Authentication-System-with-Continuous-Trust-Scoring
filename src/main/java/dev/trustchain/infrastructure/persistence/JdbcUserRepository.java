package dev.trustchain.infrastructure.persistence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.trustchain.domain.model.Permission;
import dev.trustchain.domain.model.Role;
import dev.trustchain.domain.model.User;
import dev.trustchain.domain.port.UserRepository;
import org.springframework.dao.DataAccessResourceFailureException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class JdbcUserRepository implements UserRepository {
    private final TenantSchemaRouter router;
    private final ObjectMapper objectMapper;

    public JdbcUserRepository(TenantSchemaRouter router, ObjectMapper objectMapper) {
        this.router = router;
        this.objectMapper = objectMapper;
    }

    @Override
    public Optional<User> findById(String id) {
        return find("SELECT id, tenant_id, email, attributes::text FROM users WHERE id = ?", id);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return find("SELECT id, tenant_id, email, attributes::text FROM users WHERE email = ?", email);
    }

    @Override
    public Optional<String> findPasswordHash(String userId) {
        try (Connection connection = router.openTenantConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT password_hash FROM users WHERE id = ?")) {
            statement.setString(1, userId);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? Optional.of(result.getString(1)) : Optional.empty();
            }
        } catch (SQLException exception) {
            throw new DataAccessResourceFailureException("unable to load password", exception);
        }
    }

    @Override
    public void save(User user, String passwordHash) {
        try (Connection connection = router.openTenantConnection();
             PreparedStatement statement = connection.prepareStatement("INSERT INTO users(id, tenant_id, email, password_hash, attributes) VALUES (?, ?, ?, ?, ?::jsonb) ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, password_hash = EXCLUDED.password_hash, attributes = EXCLUDED.attributes")) {
            statement.setString(1, user.id());
            statement.setString(2, user.tenantId());
            statement.setString(3, user.email());
            statement.setString(4, passwordHash);
            statement.setString(5, objectMapper.writeValueAsString(user.attributes()));
            statement.executeUpdate();
        } catch (SQLException | JsonProcessingException exception) {
            throw new DataAccessResourceFailureException("unable to save user", exception);
        }
    }

    private Optional<User> find(String sql, String value) {
        try (Connection connection = router.openTenantConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, value);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return Optional.empty();
                }
                String id = result.getString(1);
                return Optional.of(new User(id, result.getString(2), result.getString(3), roles(connection, id),
                        objectMapper.readValue(result.getString(4), new TypeReference<Map<String, String>>() { })));
            }
        } catch (SQLException | JsonProcessingException exception) {
            throw new DataAccessResourceFailureException("unable to load user", exception);
        }
    }

    private Set<Role> roles(Connection connection, String userId) throws SQLException {
        String sql = "SELECT ra.role_name, p.resource, p.action FROM role_assignments ra LEFT JOIN permissions p ON p.role_name = ra.role_name WHERE ra.user_id = ?";
        Map<String, Set<Permission>> permissions = new HashMap<>();
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, userId);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    Set<Permission> rolePermissions = permissions.computeIfAbsent(result.getString(1), ignored -> new HashSet<>());
                    if (result.getString(2) != null) {
                        rolePermissions.add(new Permission(result.getString(2), result.getString(3)));
                    }
                }
            }
        }
        Set<Role> roles = new HashSet<>();
        permissions.forEach((name, values) -> roles.add(new Role(name, values)));
        return roles;
    }
}
