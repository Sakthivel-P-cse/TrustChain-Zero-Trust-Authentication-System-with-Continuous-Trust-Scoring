package dev.trustchain.domain.policy;

import dev.trustchain.domain.model.Session;
import dev.trustchain.domain.model.TrustScore;

import java.time.Instant;
import java.util.Map;

public interface TrustSignalProvider {
    String signalName();

    int evaluate(Session session, HttpRequest request, TrustScore current);

    record HttpRequest(String remoteAddress, String method, Instant timestamp, Map<String, String> attributes) {
        public HttpRequest {
            attributes = Map.copyOf(attributes);
        }
    }
}
