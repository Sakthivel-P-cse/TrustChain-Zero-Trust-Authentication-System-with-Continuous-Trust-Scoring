package dev.trustchain.web;

import dev.trustchain.application.SessionService;
import dev.trustchain.domain.port.TenantRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public final class TrustScoreFilter extends OncePerRequestFilter {
    private final SessionService sessions;
    private final TenantRepository tenants;

    public TrustScoreFilter(SessionService sessions, TenantRepository tenants) {
        this.sessions = sessions;
        this.tenants = tenants;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/") && !path.startsWith("/admin/")
                && !path.equals("/actuator/prometheus");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken jwt) {
            String sessionId = jwt.getToken().getClaimAsString("sessionId");
            String tenantId = jwt.getToken().getClaimAsString("tenantId");
            SessionService.SessionState state = sessions.find(sessionId).orElse(null);
            if (tenantId == null || tenants.findById(tenantId).isEmpty() || state == null
                    || !state.session().active() || !state.session().tenantId().equals(tenantId)
                    || state.score().isTerminated()) {
                response.setHeader("X-TrustChain-Reason", "session_or_tenant_inactive");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            response.setHeader("X-TrustChain-Trust-Score", Integer.toString(state.score().score()));
        }
        chain.doFilter(request, response);
    }
}
