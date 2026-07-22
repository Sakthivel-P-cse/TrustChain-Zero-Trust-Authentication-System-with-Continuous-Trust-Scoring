package dev.trustchain.infrastructure.redis;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.trustchain.domain.model.Session;
import dev.trustchain.domain.model.TrustScore;
import dev.trustchain.domain.port.SessionStore;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class RedisSessionStore implements SessionStore {
    private final RedisTemplate<String, String> redis;
    private final ObjectMapper objectMapper;
    private final Duration ttl;

    public RedisSessionStore(RedisTemplate<String, String> redis, ObjectMapper objectMapper, Duration ttl) {
        this.redis = redis;
        this.objectMapper = objectMapper;
        this.ttl = ttl;
    }

    @Override
    public void save(Session session, TrustScore score) {
        redis.opsForHash().putAll(sessionKey(session.id()), Map.of(
                "id", session.id(), "userId", session.userId(), "tenantId", session.tenantId(),
                "ipAddress", session.ipAddress(), "createdAt", session.createdAt().toString(),
                "lastSeen", session.lastSeen().toString(), "active", Boolean.toString(session.active())));
        redis.expire(sessionKey(session.id()), ttl);
        updateScore(session.id(), score);
    }

    @Override
    public Optional<Session> findSession(String sessionId) {
        Map<Object, Object> values = redis.opsForHash().entries(sessionKey(sessionId));
        if (values.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new Session(text(values, "id"), text(values, "userId"), text(values, "tenantId"),
                text(values, "ipAddress"), Instant.parse(text(values, "createdAt")),
                Instant.parse(text(values, "lastSeen")), Boolean.parseBoolean(text(values, "active"))));
    }

    @Override
    public Optional<TrustScore> findScore(String sessionId) {
        Map<Object, Object> values = redis.opsForHash().entries(trustKey(sessionId));
        if (values.isEmpty()) {
            return Optional.empty();
        }
        try {
            List<String> signals = objectMapper.readValue(text(values, "recentSignals"), new TypeReference<List<String>>() { });
            return Optional.of(new TrustScore(sessionId, Integer.parseInt(text(values, "score")),
                    Instant.parse(text(values, "lastUpdated")), signals));
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("invalid trust score data", exception);
        }
    }

    @Override
    public void updateScore(String sessionId, TrustScore score) {
        try {
            redis.opsForHash().putAll(trustKey(sessionId), Map.of(
                    "score", Integer.toString(score.score()), "lastUpdated", score.lastUpdated().toString(),
                    "recentSignals", objectMapper.writeValueAsString(score.recentSignals())));
            redis.expire(trustKey(sessionId), ttl);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("unable to serialize trust score", exception);
        }
    }

    @Override
    public void terminate(String sessionId) {
        redis.opsForHash().put(sessionKey(sessionId), "active", "false");
    }

    private String text(Map<Object, Object> values, String key) {
        Object value = values.get(key);
        if (value == null) {
            throw new IllegalStateException("missing redis field " + key);
        }
        return value.toString();
    }

    private String sessionKey(String sessionId) {
        return "session:" + sessionId;
    }

    private String trustKey(String sessionId) {
        return "trust:" + sessionId;
    }
}
