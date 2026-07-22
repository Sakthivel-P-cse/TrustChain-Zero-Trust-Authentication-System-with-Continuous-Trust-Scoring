package dev.trustchain.infrastructure.persistence;

import dev.trustchain.domain.model.AuditEvent;
import dev.trustchain.domain.port.AuditLogger;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.util.List;

public final class JdbcAuditLogger implements AuditLogger {
    private final JdbcTemplate jdbc;

    public JdbcAuditLogger(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void log(AuditEvent event) {
        jdbc.update("INSERT INTO audit_log(id, session_id, tenant_id, user_id, action, resource, outcome, reason, timestamp) VALUES (?::uuid, ?, ?, ?, ?, ?, ?, ?, ?)",
                event.id(), event.sessionId(), event.tenantId(), event.userId(), event.action(), event.resource(),
                event.outcome(), event.reason(), Timestamp.from(event.timestamp()));
    }

    @Override
    public List<AuditEvent> findRecent(int limit) {
        return jdbc.query("SELECT id::text, session_id, tenant_id, user_id, action, resource, outcome, reason, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (result, row) -> new AuditEvent(result.getString(1), result.getString(2), result.getString(3),
                        result.getString(4), result.getString(5), result.getString(6), result.getString(7),
                        result.getString(8), result.getTimestamp(9).toInstant()), limit);
    }
}
