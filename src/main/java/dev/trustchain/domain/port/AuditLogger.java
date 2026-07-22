package dev.trustchain.domain.port;

import dev.trustchain.domain.model.AuditEvent;

import java.util.List;

public interface AuditLogger {
    void log(AuditEvent event);

    List<AuditEvent> findRecent(int limit);
}
