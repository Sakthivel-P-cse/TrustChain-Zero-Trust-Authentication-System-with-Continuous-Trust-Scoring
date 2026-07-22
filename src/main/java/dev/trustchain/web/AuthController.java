package dev.trustchain.web;

import dev.trustchain.application.AuthenticationService;
import dev.trustchain.application.ServiceTokenService;
import dev.trustchain.web.dto.ServiceTokenRequest;
import dev.trustchain.web.dto.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

@RestController
public final class AuthController {
    private final AuthenticationService authentication;
    private final ServiceTokenService serviceTokens;
    private final boolean demoEnabled;

    public AuthController(AuthenticationService authentication, ServiceTokenService serviceTokens,
                          @Value("${trustchain.demo.enabled}") boolean demoEnabled) {
        this.authentication = authentication;
        this.serviceTokens = serviceTokens;
        this.demoEnabled = demoEnabled;
    }

    @PostMapping("/auth/token")
    public ResponseEntity<?> token(@RequestBody Map<String, String> request, HttpServletRequest servletRequest) {
        try {
            AuthenticationService.AuthenticationResult result = authentication.authenticate(request.get("tenantId"),
                    request.get("email"), request.get("password"), servletRequest.getRemoteAddr());
            return ResponseEntity.ok(new TokenResponse(result.accessToken(), "Bearer", result.expiresIn(),
                    result.refreshToken()));
        } catch (IllegalArgumentException exception) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("reason", exception.getMessage()));
        }
    }

    @PostMapping("/service-token")
    public ResponseEntity<?> serviceToken(@RequestBody ServiceTokenRequest request,
                                          @RequestHeader(value = "X-Client-Cert-Fingerprint", required = false) String demoFingerprint,
                                          HttpServletRequest servletRequest) {
        try {
            String fingerprint = certificateFingerprint(servletRequest, demoFingerprint);
            ServiceTokenService.IssuedServiceToken result = serviceTokens.issue(new ServiceTokenService.TokenCommand(
                    request.requestingServiceId(), request.targetServiceId(), request.delegatedUserId(),
                    request.delegatedTenantId(), request.scopedAction()), fingerprint);
            return ResponseEntity.ok(Map.of("serviceToken", result.token(), "expiresAt", result.expiresAt()));
        } catch (IllegalArgumentException exception) {
            serviceTokens.auditBoundaryDenial(exception.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("reason", exception.getMessage()));
        } catch (ServiceTokenService.ServiceTokenException exception) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("reason", exception.getMessage()));
        }
    }

    @GetMapping("/api/orders")
    public Map<String, Object> orders(@RequestParam(required = false) String tenantId) {
        return Map.of("orders", java.util.List.of(Map.of("id", "order-1", "status", "ready")));
    }

    @PostMapping("/api/orders")
    public Map<String, String> createOrder() {
        return Map.of("id", "order-created", "status", "accepted");
    }

    @PostMapping("/internal/payments")
    public Map<String, String> payments() {
        return Map.of("status", "accepted");
    }

    private String certificateFingerprint(HttpServletRequest request, String demoFingerprint) {
        Object attribute = request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (attribute instanceof X509Certificate[] certificates && certificates.length > 0) {
            try {
                return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                        .digest(certificates[0].getEncoded()));
            } catch (Exception exception) {
                throw new IllegalArgumentException("client_certificate_invalid");
            }
        }
        if (demoEnabled && request.getRemoteAddr().matches("127\\.0\\.0\\.1|0:0:0:0:0:0:0:1")
                && demoFingerprint != null) {
            return demoFingerprint;
        }
        throw new IllegalArgumentException("client_certificate_required");
    }
}
