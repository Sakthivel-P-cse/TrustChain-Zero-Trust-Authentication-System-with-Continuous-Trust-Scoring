package dev.trustchain.domain.model;

import java.time.Instant;

public record AuditEvent(String id, String sessionId, String tenantId, String userId, String action,
                         String resource, String outcome, String reason, Instant timestamp) {
}
