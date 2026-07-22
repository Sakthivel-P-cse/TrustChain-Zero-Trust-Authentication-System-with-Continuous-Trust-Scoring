package dev.trustchain.infrastructure.signals;

import dev.trustchain.domain.model.Session;
import dev.trustchain.domain.model.TrustScore;
import dev.trustchain.domain.policy.TrustSignalProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;

public final class FailedPermissionSignalProvider implements TrustSignalProvider {
    private static final Logger logger = LoggerFactory.getLogger(FailedPermissionSignalProvider.class);
    private final RedisTemplate<String, String> redis;
    private final Duration window;
    private final int threshold;

    public FailedPermissionSignalProvider(RedisTemplate<String, String> redis, Duration window, int threshold) {
        this.redis = redis;
        this.window = window;
        this.threshold = threshold;
    }

    @Override
    public String signalName() {
        return "failed_permission_probe";
    }

    @Override
    public int evaluate(Session session, HttpRequest request, TrustScore current) {
        if (!Boolean.parseBoolean(request.attributes().getOrDefault("permissionDenied", "false"))) {
            return 0;
        }
        String key = "signal:permission:" + session.id();
        Long count = redis.opsForValue().increment(key);
        redis.expire(key, window);
        String latchKey = key + ":fired";
        if (count != null && count > threshold
                && Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(latchKey, "true", window))) {
            logger.info("Trust signal {} fired for session {}", signalName(), session.id());
            return -25;
        }
        return 0;
    }
}
