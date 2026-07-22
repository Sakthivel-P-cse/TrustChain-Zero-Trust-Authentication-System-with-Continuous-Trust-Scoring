package dev.trustchain.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import dev.trustchain.application.AuthenticationService;
import dev.trustchain.application.AuthorizationService;
import dev.trustchain.application.ServiceTokenService;
import dev.trustchain.application.SessionService;
import dev.trustchain.application.TenantProvisioningService;
import dev.trustchain.domain.model.ServiceIdentity;
import dev.trustchain.domain.model.Tenant;
import dev.trustchain.domain.policy.AbacEvaluator;
import dev.trustchain.domain.policy.RbacEvaluator;
import dev.trustchain.domain.policy.TrustScoreEvaluator;
import dev.trustchain.domain.policy.TrustSignalProvider;
import dev.trustchain.domain.port.AuditLogger;
import dev.trustchain.domain.port.SessionStore;
import dev.trustchain.domain.port.TenantRepository;
import dev.trustchain.domain.port.UserRepository;
import dev.trustchain.infrastructure.persistence.JdbcAuditLogger;
import dev.trustchain.infrastructure.persistence.JdbcTenantRepository;
import dev.trustchain.infrastructure.persistence.JdbcUserRepository;
import dev.trustchain.infrastructure.persistence.TenantSchemaRouter;
import dev.trustchain.infrastructure.redis.RedisSessionStore;
import dev.trustchain.infrastructure.signals.FailedPermissionSignalProvider;
import dev.trustchain.infrastructure.signals.ImpossibleTravelSignalProvider;
import dev.trustchain.infrastructure.signals.IpChangeSignalProvider;
import dev.trustchain.infrastructure.signals.RequestRateSignalProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Configuration
public class SecurityConfig {
    @Bean
    @Primary
    RedisTemplate<String, String> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, String> redis = new RedisTemplate<>();
        StringRedisSerializer serializer = new StringRedisSerializer();
        redis.setConnectionFactory(connectionFactory);
        redis.setKeySerializer(serializer);
        redis.setValueSerializer(serializer);
        redis.setHashKeySerializer(serializer);
        redis.setHashValueSerializer(serializer);
        redis.afterPropertiesSet();
        return redis;
    }

    @Bean
    @Primary
    DataSource physicalDataSource(DataSourceProperties properties) {
        return properties.initializeDataSourceBuilder().build();
    }

    @Bean
    TenantSchemaRouter tenantSchemaRouter(@Qualifier("physicalDataSource") DataSource dataSource) {
        return new TenantSchemaRouter(dataSource);
    }

    @Bean
    TenantRepository tenantRepository(JdbcTemplate jdbc) {
        return new JdbcTenantRepository(jdbc);
    }

    @Bean
    UserRepository userRepository(TenantSchemaRouter router, ObjectMapper objectMapper) {
        return new JdbcUserRepository(router, objectMapper);
    }

    @Bean
    AuditLogger auditLogger(JdbcTemplate jdbc) {
        return new JdbcAuditLogger(jdbc);
    }

    @Bean
    SessionStore sessionStore(RedisTemplate<String, String> redis, ObjectMapper objectMapper,
                              @Value("${trustchain.jwt.refresh-token-ttl}") long ttl) {
        return new RedisSessionStore(redis, objectMapper, Duration.ofSeconds(ttl));
    }

    @Bean
    List<TrustSignalProvider> trustSignals(RedisTemplate<String, String> redis,
                                           @Value("${trustchain.session.sliding-window-seconds}") int window,
                                           @Value("${trustchain.session.rate-threshold-multiplier}") double multiplier,
                                           @Value("${trustchain.session.failed-permission-window-minutes}") long failedWindow,
                                           @Value("${trustchain.session.failed-permission-threshold}") int failedThreshold) {
        return List.of(new IpChangeSignalProvider(redis), new RequestRateSignalProvider(redis, window, multiplier),
                new FailedPermissionSignalProvider(redis, Duration.ofMinutes(failedWindow), failedThreshold),
                new ImpossibleTravelSignalProvider(redis));
    }

    @Bean
    TrustScoreEvaluator trustScoreEvaluator(List<TrustSignalProvider> providers) {
        return new TrustScoreEvaluator(providers);
    }

    @Bean
    SessionService sessionService(SessionStore store, TrustScoreEvaluator evaluator) {
        return new SessionService(store, evaluator);
    }

    @Bean
    RbacEvaluator rbacEvaluator() {
        return new RbacEvaluator();
    }

    @Bean
    AbacEvaluator abacEvaluator() {
        AbacEvaluator.Rule tenantRule = (user, resource, attributes) ->
                resource.ownerTenantId().equals(user.tenantId()) ? Optional.empty() : Optional.of("cross_tenant_blocked");
        AbacEvaluator.Rule clearanceRule = (user, resource, attributes) -> {
            String clearance = user.attributes().get("clearance_level");
            return clearance != null && Integer.parseInt(clearance) < resource.sensitivityLevel()
                    ? Optional.of("clearance_insufficient") : Optional.empty();
        };
        AbacEvaluator.Rule hoursRule = (user, resource, attributes) -> {
            String hours = user.attributes().get("allowed_hours");
            if (hours == null) {
                return Optional.empty();
            }
            String[] range = hours.split("-");
            int hour = Integer.parseInt(attributes.getOrDefault("hour_of_day", "0"));
            return hour < Integer.parseInt(range[0]) || hour > Integer.parseInt(range[1])
                    ? Optional.of("outside_allowed_hours") : Optional.empty();
        };
        return new AbacEvaluator(List.of(tenantRule, clearanceRule, hoursRule));
    }

    @Bean
    AuthorizationService authorizationService(SessionService sessions, UserRepository users, RbacEvaluator rbac,
                                              TenantRepository tenants, AbacEvaluator abac, AuditLogger audit,
                                              AuthorizationService.AbacPolicySource policies) {
        return new AuthorizationService(sessions, users, tenants, rbac, abac, audit, policies);
    }

    @Bean
    AuthorizationService.AbacPolicySource abacPolicySource(TenantSchemaRouter router) {
        return tenantId -> router.withTenant(tenantId, () -> {
            try (Connection connection = router.openTenantConnection();
                 PreparedStatement statement = connection.prepareStatement(
                         "SELECT rule_type FROM abac_rules ORDER BY priority");
                 ResultSet result = statement.executeQuery()) {
                java.util.ArrayList<AbacEvaluator.Rule> rules = new java.util.ArrayList<>();
                while (result.next()) {
                    rules.add(abacRule(result.getString(1)));
                }
                return List.copyOf(rules);
            } catch (Exception exception) {
                throw new IllegalStateException("abac_policy_load_failed", exception);
            }
        });
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtEncoder jwtEncoder(@Value("${trustchain.jwt.secret}") String secret) {
        return new NimbusJwtEncoder(new ImmutableSecret<>(secretKey(secret)));
    }

    @Bean
    JwtDecoder jwtDecoder(@Value("${trustchain.jwt.secret}") String secret) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(secretKey(secret))
                .macAlgorithm(MacAlgorithm.HS256).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer("trustchain"),
                new JwtClaimValidator<>("tokenType", "access"::equals)));
        return decoder;
    }

    @Bean
    AuthenticationService.TokenIssuer tokenIssuer(JwtEncoder encoder) {
        return (claims, ttl, refresh) -> encode(encoder, claims, ttl, refresh ? "refresh" : "access");
    }

    @Bean
    AuthenticationService authenticationService(UserRepository users, TenantRepository tenants, SessionService sessions,
                                                PasswordEncoder passwords, AuthenticationService.TokenIssuer issuer,
                                                TenantSchemaRouter router,
                                                @Value("${trustchain.jwt.access-token-ttl}") long accessTtl,
                                                @Value("${trustchain.jwt.refresh-token-ttl}") long refreshTtl) {
        return new AuthenticationService(users, tenants, sessions, passwords::matches, issuer, router,
                Duration.ofSeconds(accessTtl), Duration.ofSeconds(refreshTtl));
    }

    @Bean
    ServiceTokenService.ServiceIdentitySource serviceIdentitySource(JdbcTemplate jdbc) {
        return serviceId -> jdbc.query("SELECT s.service_id, s.tenant_id, s.certificate_fingerprint, s.allowed_actions FROM service_identities s JOIN tenants t ON t.id = s.tenant_id AND t.active WHERE s.service_id = ?",
                result -> {
                    if (!result.next()) {
                        return Optional.empty();
                    }
                    String[] actions = (String[]) result.getArray(4).getArray();
                    return Optional.of(new ServiceTokenService.ServiceIdentityRecord(
                            new ServiceIdentity(result.getString(1), result.getString(2), result.getString(3)),
                            Set.copyOf(Arrays.asList(actions))));
                }, serviceId);
    }

    @Bean
    ServiceTokenService.ServiceTokenCodec serviceTokenCodec(
            @Value("${trustchain.jwt.service-secret}") String secret) {
        SecretKey key = secretKey(secret);
        JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableSecret<>(key));
        JwtDecoder decoder = NimbusJwtDecoder.withSecretKey(key).macAlgorithm(MacAlgorithm.HS256).build();
        return new ServiceTokenService.ServiceTokenCodec() {
            @Override
            public String encode(Map<String, Object> claims, Duration ttl) {
                return SecurityConfig.this.encode(encoder, claims, ttl, "service");
            }

            @Override
            public ServiceTokenService.DecodedServiceToken decode(String token) {
                try {
                    var jwt = decoder.decode(token);
                    return new ServiceTokenService.DecodedServiceToken(jwt.getId(),
                            jwt.getClaimAsString("requestingServiceId"), jwt.getClaimAsString("targetServiceId"),
                            jwt.getClaimAsString("delegatedUserId"), jwt.getClaimAsString("delegatedTenantId"),
                            jwt.getClaimAsString("scopedAction"), jwt.getExpiresAt());
                } catch (RuntimeException exception) {
                    throw new ServiceTokenService.ServiceTokenException("service_token_invalid");
                }
            }
        };
    }

    @Bean
    ServiceTokenService.TokenReplayStore tokenReplayStore(RedisTemplate<String, String> redis) {
        return (jti, ttl) -> Boolean.TRUE.equals(redis.opsForValue().setIfAbsent("service:jti:" + jti, "used", ttl));
    }

    @Bean
    ServiceTokenService serviceTokenService(ServiceTokenService.ServiceIdentitySource identities,
                                            ServiceTokenService.ServiceTokenCodec codec,
                                            ServiceTokenService.TokenReplayStore replayStore,
                                            AuditLogger audit,
                                            @Value("${trustchain.jwt.service-token-ttl}") long ttl) {
        return new ServiceTokenService(identities, codec, replayStore, Duration.ofSeconds(ttl), audit);
    }

    @Bean
    TenantProvisioningService.TenantSchemaManager tenantSchemaManager(
                                                                       @Qualifier("physicalDataSource") DataSource dataSource,
                                                                       PasswordEncoder passwordEncoder) {
        return (tenant, user) -> {
            String schema = checkedSchema(tenant.schemaName());
            try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
                statement.execute("CREATE SCHEMA IF NOT EXISTS " + schema);
                statement.execute("CREATE TABLE IF NOT EXISTS " + schema + ".users (id VARCHAR(36) PRIMARY KEY, tenant_id VARCHAR(36) NOT NULL, email VARCHAR(255) NOT NULL UNIQUE, password_hash VARCHAR(100) NOT NULL, attributes JSONB NOT NULL DEFAULT '{}'::jsonb)");
                statement.execute("CREATE TABLE IF NOT EXISTS " + schema + ".roles (name VARCHAR(100) PRIMARY KEY)");
                statement.execute("CREATE TABLE IF NOT EXISTS " + schema + ".permissions (role_name VARCHAR(100) REFERENCES " + schema + ".roles(name), resource VARCHAR(100), action VARCHAR(100), PRIMARY KEY(role_name, resource, action))");
                statement.execute("CREATE TABLE IF NOT EXISTS " + schema + ".role_assignments (user_id VARCHAR(36) REFERENCES " + schema + ".users(id), role_name VARCHAR(100) REFERENCES " + schema + ".roles(name), PRIMARY KEY(user_id, role_name))");
                statement.execute("CREATE TABLE IF NOT EXISTS " + schema + ".abac_rules (name VARCHAR(100) PRIMARY KEY, priority INTEGER NOT NULL, rule_type VARCHAR(100) NOT NULL, parameters JSONB NOT NULL)");
                statement.execute("INSERT INTO " + schema + ".roles(name) VALUES ('admin'), ('editor'), ('viewer') ON CONFLICT DO NOTHING");
                statement.execute("INSERT INTO " + schema + ".permissions(role_name, resource, action) VALUES ('editor','orders','read'), ('editor','orders','write'), ('viewer','orders','read') ON CONFLICT DO NOTHING");
                statement.execute("INSERT INTO " + schema + ".abac_rules(name, priority, rule_type, parameters) VALUES ('tenant-owner',1,'tenant_match','{}'), ('clearance',2,'max_sensitivity','{}'), ('allowed-hours',3,'time_window','{}') ON CONFLICT DO NOTHING");
                if (user != null) {
                    try (PreparedStatement insertUser = connection.prepareStatement("INSERT INTO " + schema + ".users(id, tenant_id, email, password_hash, attributes) VALUES (?, ?, ?, ?, ?::jsonb) ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email, password_hash = EXCLUDED.password_hash, attributes = EXCLUDED.attributes")) {
                        insertUser.setString(1, user.id());
                        insertUser.setString(2, tenant.id());
                        insertUser.setString(3, user.email());
                        insertUser.setString(4, passwordEncoder.encode(user.password()));
                        insertUser.setString(5, "{\"clearance_level\":\"5\",\"allowed_hours\":\"0-23\"}");
                        insertUser.executeUpdate();
                    }
                    try (PreparedStatement assign = connection.prepareStatement("INSERT INTO " + schema + ".role_assignments(user_id, role_name) VALUES (?, ?) ON CONFLICT DO NOTHING")) {
                        assign.setString(1, user.id());
                        assign.setString(2, tenant.id().equals("org-a") ? "editor" : "viewer");
                        assign.executeUpdate();
                    }
                    if (tenant.id().equals("org-a")) {
                        try (PreparedStatement assignAdmin = connection.prepareStatement("INSERT INTO " + schema + ".role_assignments(user_id, role_name) VALUES (?, 'admin') ON CONFLICT DO NOTHING")) {
                            assignAdmin.setString(1, user.id());
                            assignAdmin.executeUpdate();
                        }
                    }
                }
            } catch (Exception exception) {
                throw new IllegalStateException("tenant_schema_provisioning_failed", exception);
            }
        };
    }

    @Bean
    TenantProvisioningService tenantProvisioningService(TenantRepository tenants,
                                                         TenantProvisioningService.TenantSchemaManager schemas) {
        return new TenantProvisioningService(tenants, schemas);
    }

    @Bean
    ApplicationRunner demoTenantSeeder(TenantProvisioningService provisioning) {
        return arguments -> provisioning.seedDemoTenants();
    }

    @Bean
    AuthorizationFilter authorizationFilter(AuthorizationService authorization, TenantSchemaRouter router,
                                             ObjectMapper objectMapper,
                                             @Value("${trustchain.demo.trust-forwarded-for}") boolean forwarded,
                                             @Value("${trustchain.demo.enabled}") boolean demoEnabled) {
        return new AuthorizationFilter(authorization, router, objectMapper, forwarded && demoEnabled);
    }

    @Bean
    TrustScoreFilter trustScoreFilter(SessionService sessions, TenantRepository tenants) {
        return new TrustScoreFilter(sessions, tenants);
    }

    @Bean
    ServiceTokenFilter serviceTokenFilter(ServiceTokenService serviceTokens, ObjectMapper objectMapper) {
        return new ServiceTokenFilter(serviceTokens, objectMapper);
    }

    @Bean
    FilterRegistrationBean<AuthorizationFilter> authorizationFilterRegistration(AuthorizationFilter filter) {
        FilterRegistrationBean<AuthorizationFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    FilterRegistrationBean<TrustScoreFilter> trustScoreFilterRegistration(TrustScoreFilter filter) {
        FilterRegistrationBean<TrustScoreFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    FilterRegistrationBean<ServiceTokenFilter> serviceTokenFilterRegistration(ServiceTokenFilter filter) {
        FilterRegistrationBean<ServiceTokenFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    @Order(1)
    SecurityFilterChain internalSecurity(HttpSecurity http, ServiceTokenFilter serviceTokenFilter) throws Exception {
        return http.securityMatcher(request -> request.getRequestURI().startsWith("/internal/"))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
                .addFilterBefore(serviceTokenFilter, BearerTokenAuthenticationFilter.class)
                .build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain apiSecurity(HttpSecurity http, AuthorizationFilter authorizationFilter,
                                    TrustScoreFilter trustScoreFilter) throws Exception {
        JwtGrantedAuthoritiesConverter authorities = new JwtGrantedAuthoritiesConverter();
        authorities.setAuthoritiesClaimName("roles");
        authorities.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authorities);
        return http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/auth/token", "/service-token", "/actuator/health").permitAll()
                        .requestMatchers(request -> request.getRequestURI().startsWith("/admin/")).hasRole("admin")
                        .anyRequest().authenticated())
                .x509(Customizer.withDefaults())
                .oauth2ResourceServer(resource -> resource.jwt(jwt -> jwt.jwtAuthenticationConverter(converter)))
                .addFilterAfter(authorizationFilter, BearerTokenAuthenticationFilter.class)
                .addFilterAfter(trustScoreFilter, AuthorizationFilter.class)
                .build();
    }

    private String encode(JwtEncoder encoder, Map<String, Object> claims, Duration ttl, String tokenType) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder builder = JwtClaimsSet.builder().issuer("trustchain").issuedAt(now)
                .expiresAt(now.plus(ttl)).id(UUID.randomUUID().toString()).claim("tokenType", tokenType);
        claims.forEach(builder::claim);
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), builder.build()))
                .getTokenValue();
    }

    private SecretKey secretKey(String secret) {
        return new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    private String checkedSchema(String schema) {
        if (!schema.matches("tenant_[a-zA-Z0-9_]{1,50}")) {
            throw new IllegalArgumentException("invalid_schema_name");
        }
        return schema;
    }

    private AbacEvaluator.Rule abacRule(String type) {
        return switch (type) {
            case "tenant_match" -> (user, resource, attributes) -> resource.ownerTenantId().equals(user.tenantId())
                    ? Optional.empty() : Optional.of("cross_tenant_blocked");
            case "max_sensitivity" -> (user, resource, attributes) -> {
                String clearance = user.attributes().get("clearance_level");
                return clearance != null && Integer.parseInt(clearance) < resource.sensitivityLevel()
                        ? Optional.of("clearance_insufficient") : Optional.empty();
            };
            case "time_window" -> (user, resource, attributes) -> {
                String hours = user.attributes().get("allowed_hours");
                if (hours == null) {
                    return Optional.empty();
                }
                String[] range = hours.split("-");
                int hour = Integer.parseInt(attributes.getOrDefault("hour_of_day", "0"));
                return hour < Integer.parseInt(range[0]) || hour > Integer.parseInt(range[1])
                        ? Optional.of("outside_allowed_hours") : Optional.empty();
            };
            default -> throw new IllegalArgumentException("unsupported_abac_rule");
        };
    }
}
