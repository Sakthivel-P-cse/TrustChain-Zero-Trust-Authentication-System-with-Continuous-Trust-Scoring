package dev.trustchain;

import dev.trustchain.domain.model.Session;
import dev.trustchain.domain.model.TrustScore;
import dev.trustchain.domain.policy.TrustScoreEvaluator;
import dev.trustchain.domain.policy.TrustSignalProvider;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class TrustScoreEvaluatorTest {
    private final Session session = new Session("session", "user", "org-a", "127.0.0.1",
            Instant.now(), Instant.now(), true);
    private final TrustSignalProvider.HttpRequest request = new TrustSignalProvider.HttpRequest(
            "127.0.0.1", "GET", Instant.now(), Map.of());

    @Test
    void stableSignalsKeepFreshScoreAtOneHundred() {
        TrustScore score = evaluator(0, 0).evaluate(session, request, score(100));
        assertThat(score.score()).isEqualTo(100);
        assertThat(score.recentSignals()).isEmpty();
    }

    @Test
    void ipChangeDropsScoreByFifteen() {
        assertThat(evaluator(-15).evaluate(session, request, score(100)).score()).isEqualTo(85);
    }

    @Test
    void impossibleTravelDropsScoreByForty() {
        TrustScore score = new TrustScoreEvaluator(List.of(new Signal("impossible_travel", -40),
                new Signal("stable", 0))).evaluate(session, request, score(100));
        assertThat(score.score()).isEqualTo(60);
        assertThat(score.recentSignals()).containsExactly("impossible_travel");
    }

    @Test
    void multipleSignalsSumAndClamp() {
        assertThat(evaluator(-40, -25, -60).evaluate(session, request, score(100)).score()).isZero();
        assertThat(evaluator(80, 80).evaluate(session, request, score(100)).score()).isEqualTo(100);
    }

    @Test
    void recoveryWithoutReauthenticationIsCappedAtEighty() {
        assertThat(evaluator(50).evaluate(session, request, score(60)).score()).isEqualTo(80);
    }

    @Test
    void recoveryDoesNotReduceScoreAlreadyAboveCap() {
        assertThat(evaluator(10).evaluate(session, request, score(85)).score()).isEqualTo(85);
    }

    @Test
    void scoreBelowFortyTerminatesSession() {
        assertThat(score(39).isTerminated()).isTrue();
    }

    @Test
    void fullReauthenticationRestoresFullAccess() {
        assertThat(score(100).isFullAccess()).isTrue();
    }

    private TrustScoreEvaluator evaluator(int... deltas) {
        List<TrustSignalProvider> providers = java.util.Arrays.stream(deltas)
                .mapToObj(delta -> (TrustSignalProvider) new Signal("signal_" + delta, delta)).toList();
        return new TrustScoreEvaluator(providers);
    }

    private TrustScore score(int value) {
        return new TrustScore(session.id(), value, Instant.now(), List.of());
    }

    private record Signal(String signalName, int delta) implements TrustSignalProvider {
        @Override
        public int evaluate(Session ignoredSession, HttpRequest ignoredRequest, TrustScore ignoredScore) {
            return delta;
        }
    }
}
