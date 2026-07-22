package dev.trustchain.infrastructure.signals;

import dev.trustchain.domain.model.Session;
import dev.trustchain.domain.model.TrustScore;
import dev.trustchain.domain.policy.TrustSignalProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;

public final class IpChangeSignalProvider implements TrustSignalProvider {
    private static final Logger logger = LoggerFactory.getLogger(IpChangeSignalProvider.class);
    private final RedisTemplate<String, String> redis;

    public IpChangeSignalProvider(RedisTemplate<String, String> redis) {
        this.redis = redis;
    }

    @Override
    public String signalName() {
        return "ip_change";
    }

    @Override
    public int evaluate(Session session, HttpRequest request, TrustScore current) {
        String key = "signal:ip:" + session.id();
        String previous = redis.opsForValue().get(key);
        if (previous == null) {
            previous = session.ipAddress();
        }
        redis.opsForValue().set(key, request.remoteAddress());
        if (!previous.equals(request.remoteAddress())) {
            logger.info("Trust signal {} fired for session {}", signalName(), session.id());
            return -15;
        }
        return 0;
    }
}
