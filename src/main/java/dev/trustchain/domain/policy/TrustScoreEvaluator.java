package dev.trustchain.domain.policy;

import dev.trustchain.domain.model.Session;
import dev.trustchain.domain.model.TrustScore;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class TrustScoreEvaluator {
    private final List<TrustSignalProvider> providers;

    public TrustScoreEvaluator(List<TrustSignalProvider> providers) {
        this.providers = List.copyOf(providers);
    }

    public TrustScore evaluate(Session session, TrustSignalProvider.HttpRequest request, TrustScore current) {
        int delta = 0;
        List<String> fired = new ArrayList<>();
        for (TrustSignalProvider provider : providers) {
            int contribution = provider.evaluate(session, request, current);
            if (contribution != 0) {
                delta += contribution;
                fired.add(provider.signalName());
            }
        }
        int updated = Math.max(0, Math.min(100, current.score() + delta));
        if (delta > 0 && current.score() < 100) {
            updated = current.score() >= 80 ? current.score() : Math.min(80, updated);
        }
        return new TrustScore(session.id(), updated, Instant.now(), fired);
    }
}
