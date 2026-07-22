package dev.trustchain.infrastructure.persistence;

import dev.trustchain.application.AuthenticationService;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.function.Supplier;

public final class TenantSchemaRouter extends AbstractRoutingDataSource implements AuthenticationService.TenantScope {
    private final ThreadLocal<String> tenantContext = new ThreadLocal<>();
    private final DataSource dataSource;

    public TenantSchemaRouter(DataSource dataSource) {
        this.dataSource = dataSource;
        setTargetDataSources(Map.of("default", dataSource));
        setDefaultTargetDataSource(dataSource);
        afterPropertiesSet();
    }

    @Override
    protected Object determineCurrentLookupKey() {
        return currentTenant();
    }

    public void useTenant(String tenantId) {
        tenantContext.set(validateTenantId(tenantId));
    }

    public void clear() {
        tenantContext.remove();
    }

    @Override
    public <T> T withTenant(String tenantId, Supplier<T> operation) {
        String previous = tenantContext.get();
        useTenant(tenantId);
        try {
            return operation.get();
        } finally {
            if (previous == null) {
                clear();
            } else {
                tenantContext.set(previous);
            }
        }
    }

    public Connection openTenantConnection() throws SQLException {
        String tenantId = currentTenant();
        if (tenantId == null) {
            throw new IllegalStateException("tenant_context_missing");
        }
        return scopedConnection(dataSource.getConnection(), tenantId);
    }

    @Override
    public Connection getConnection() throws SQLException {
        String tenantId = currentTenant();
        Connection connection = dataSource.getConnection();
        return tenantId == null ? connection : scopedConnection(connection, tenantId);
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        String tenantId = currentTenant();
        Connection connection = dataSource.getConnection(username, password);
        return tenantId == null ? connection : scopedConnection(connection, tenantId);
    }

    public String schemaName(String tenantId) {
        return "tenant_" + validateTenantId(tenantId).replace('-', '_');
    }

    private String currentTenant() {
        String explicit = tenantContext.get();
        if (explicit != null) {
            return explicit;
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwt) {
            return validateTenantId(jwt.getToken().getClaimAsString("tenantId"));
        }
        return null;
    }

    private String validateTenantId(String tenantId) {
        if (tenantId == null || !tenantId.matches("[a-zA-Z0-9-]{1,36}")) {
            throw new IllegalArgumentException("invalid_tenant_id");
        }
        return tenantId;
    }

    private Connection scopedConnection(Connection connection, String tenantId) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("SET search_path TO " + schemaName(tenantId) + ", public");
        } catch (SQLException exception) {
            connection.close();
            throw exception;
        }
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[]{Connection.class},
                (proxy, method, arguments) -> {
                    if (method.getName().equals("close") && (arguments == null || arguments.length == 0)) {
                        try (Statement statement = connection.createStatement()) {
                            statement.execute("RESET search_path");
                        } finally {
                            connection.close();
                        }
                        return null;
                    }
                    try {
                        return method.invoke(connection, arguments);
                    } catch (InvocationTargetException exception) {
                        throw exception.getCause();
                    }
                });
    }
}
