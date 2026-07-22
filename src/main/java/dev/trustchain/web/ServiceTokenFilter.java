package dev.trustchain.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.trustchain.application.ServiceTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public final class ServiceTokenFilter extends OncePerRequestFilter {
    private final ServiceTokenService serviceTokens;
    private final ObjectMapper objectMapper;

    public ServiceTokenFilter(ServiceTokenService serviceTokens, ObjectMapper objectMapper) {
        this.serviceTokens = serviceTokens;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/internal/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            reject(response, "service_token_missing");
            return;
        }
        String action = request.getHeader("X-Scoped-Action");
        if (action == null) {
            action = request.getMethod().equals("GET") ? "read:payments" : "write:payments";
        }
        try {
            ServiceTokenService.ValidatedServiceToken validated = serviceTokens.validateAndConsume(
                    authorization.substring(7), "payment-service", action);
            Map<String, String> principal = Map.of("serviceId", validated.serviceId(),
                    "userId", validated.delegatedUserId(), "tenantId", validated.delegatedTenantId());
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(principal, null, List.of()));
            chain.doFilter(request, response);
        } catch (ServiceTokenService.ServiceTokenException exception) {
            reject(response, exception.getMessage());
        }
    }

    private void reject(HttpServletResponse response, String reason) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setHeader("X-TrustChain-Reason", reason);
        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), Map.of("reason", reason));
    }
}
