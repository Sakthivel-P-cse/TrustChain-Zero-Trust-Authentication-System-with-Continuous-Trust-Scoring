package dev.trustchain.domain.model;

import java.time.Instant;
import java.util.List;

public record TrustScore(String sessionId, int score, Instant lastUpdated, List<String> recentSignals) {
    public TrustScore {
        if (score < 0 || score > 100) {
            throw new IllegalArgumentException("score must be between 0 and 100");
        }
        recentSignals = List.copyOf(recentSignals);
    }

    public boolean isFullAccess() {
        return score >= 70;
    }

    public boolean isReadOnly() {
        return score >= 40 && score < 70;
    }

    public boolean isTerminated() {
        return score < 40;
    }
}
