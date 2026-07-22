package dev.trustchain.domain.port;

import dev.trustchain.domain.model.Session;
import dev.trustchain.domain.model.TrustScore;

import java.util.Optional;

public interface SessionStore {
    void save(Session session, TrustScore score);

    Optional<Session> findSession(String sessionId);

    Optional<TrustScore> findScore(String sessionId);

    void updateScore(String sessionId, TrustScore score);

    void terminate(String sessionId);
}
