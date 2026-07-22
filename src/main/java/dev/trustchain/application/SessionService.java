package dev.trustchain.application;

import dev.trustchain.domain.model.Session;
import dev.trustchain.domain.model.TrustScore;
import dev.trustchain.domain.policy.TrustScoreEvaluator;
import dev.trustchain.domain.policy.TrustSignalProvider;
import dev.trustchain.domain.port.SessionStore;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public final class SessionService {
    private final SessionStore store;
    private final TrustScoreEvaluator evaluator;

    public SessionService(SessionStore store, TrustScoreEvaluator evaluator) {
        this.store = store;
        this.evaluator = evaluator;
    }

    public void create(Session session) {
        store.save(session, new TrustScore(session.id(), 100, Instant.now(), List.of()));
    }

    public Optional<SessionState> find(String sessionId) {
        return store.findSession(sessionId)
                .flatMap(session -> store.findScore(sessionId).map(score -> new SessionState(session, score)));
    }

    public TrustScore evaluate(String sessionId, TrustSignalProvider.HttpRequest request) {
        SessionState state = find(sessionId).orElseThrow(() -> new IllegalArgumentException("session_not_found"));
        TrustScore updated = evaluator.evaluate(state.session(), request, state.score());
        store.updateScore(sessionId, updated);
        if (updated.isTerminated()) {
            store.terminate(sessionId);
        }
        return updated;
    }

    public void terminate(String sessionId) {
        store.terminate(sessionId);
    }

    public record SessionState(Session session, TrustScore score) {
    }
}
