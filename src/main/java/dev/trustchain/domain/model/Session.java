package dev.trustchain.domain.model;

import java.time.Instant;

public record Session(String id, String userId, String tenantId, String ipAddress, Instant createdAt,
                      Instant lastSeen, boolean active) {
}
