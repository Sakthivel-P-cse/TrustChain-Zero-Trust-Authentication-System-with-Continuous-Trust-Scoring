package dev.trustchain.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.trustchain.application.AuthorizationService;
import dev.trustchain.infrastructure.persistence.TenantSchemaRouter;
import dev.trustchain.web.dto.AuthDecisionResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalTime;
import java.util.Map;

public final class AuthorizationFilter extends OncePerRequestFilter {
    private final AuthorizationService authorization;
    private final TenantSchemaRouter router;
    private final ObjectMapper objectMapper;
    private final boolean trustForwardedFor;

    public AuthorizationFilter(AuthorizationService authorization, TenantSchemaRouter router,
                               ObjectMapper objectMapper, boolean trustForwardedFor) {
        this.authorization = authorization;
        this.router = router;
        this.objectMapper = objectMapper;
        this.trustForwardedFor = trustForwardedFor;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication current = SecurityContextHolder.getContext().getAuthentication();
        if (!(current instanceof JwtAuthenticationToken jwt)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        String tenantId = jwt.getToken().getClaimAsString("tenantId");
        String requestedTenant = request.getParameter("tenantId");
        if (requestedTenant != null && !requestedTenant.equals(tenantId)) {
            reject(response, HttpServletResponse.SC_FORBIDDEN, "tenant_claim_mismatch", 0);
            return;
        }
        router.useTenant(tenantId);
        try {
            String resource = request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1);
            String action = request.getMethod().equals("GET") ? "read" : "write";
            String remoteAddress = trustForwardedFor && request.getHeader("X-Forwarded-For") != null
                    ? request.getHeader("X-Forwarded-For").split(",")[0].trim() : request.getRemoteAddr();
            AuthorizationService.AuthorizationDecision decision = authorization.authorize(
                    new AuthorizationService.AuthorizationRequest(jwt.getToken().getClaimAsString("sessionId"),
                            tenantId, jwt.getToken().getClaimAsString("userId"), request.getMethod(), resource,
                            action, remoteAddress, tenantId, 1,
                            Map.of("hour_of_day", Integer.toString(LocalTime.now().getHour()))));
            response.setHeader("X-TrustChain-Trust-Score", Integer.toString(decision.trustScore()));
            if (!decision.allowed()) {
                reject(response, decision.status(), decision.reason(), decision.trustScore());
                return;
            }
            request.setAttribute("trustchainEvaluated", Boolean.TRUE);
            chain.doFilter(request, response);
        } finally {
            router.clear();
        }
    }

    private void reject(HttpServletResponse response, int status, String reason, int score) throws IOException {
        response.setStatus(status);
        response.setHeader("X-TrustChain-Reason", reason);
        response.setHeader("X-TrustChain-Trust-Score", Integer.toString(score));
        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), new AuthDecisionResponse(false, reason, score));
    }
}
