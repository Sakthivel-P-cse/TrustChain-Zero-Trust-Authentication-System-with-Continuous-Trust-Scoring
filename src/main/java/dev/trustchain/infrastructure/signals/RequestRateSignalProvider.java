package dev.trustchain.infrastructure.signals;

import dev.trustchain.domain.model.Session;
import dev.trustchain.domain.model.TrustScore;
import dev.trustchain.domain.policy.TrustSignalProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.util.UUID;

public final class RequestRateSignalProvider implements TrustSignalProvider {
    private static final Logger logger = LoggerFactory.getLogger(RequestRateSignalProvider.class);
    private final RedisTemplate<String, String> redis;
    private final int windowSeconds;
    private final double multiplier;

    public RequestRateSignalProvider(RedisTemplate<String, String> redis, int windowSeconds, double multiplier) {
        this.redis = redis;
        this.windowSeconds = windowSeconds;
        this.multiplier = multiplier;
    }

    @Override
    public String signalName() {
        return "request_rate_spike";
    }

    @Override
    public int evaluate(Session session, HttpRequest request, TrustScore current) {
        String key = "signal:rate:" + session.id();
        double now = request.timestamp().toEpochMilli();
        redis.opsForZSet().removeRangeByScore(key, 0, now - windowSeconds * 1000L);
        redis.opsForZSet().add(key, now + ":" + UUID.randomUUID(), now);
        redis.expire(key, Duration.ofSeconds(windowSeconds));
        Long currentRate = redis.opsForZSet().zCard(key);
        String averageKey = key + ":average";
        String storedAverage = redis.opsForValue().get(averageKey);
        double average = storedAverage == null ? Math.max(1, currentRate) : Double.parseDouble(storedAverage);
        double updatedAverage = average * 0.95 + currentRate * 0.05;
        redis.opsForValue().set(averageKey, Double.toString(updatedAverage), Duration.ofHours(24));
        String latchKey = key + ":fired";
        boolean spike = currentRate >= 10 && currentRate > average * multiplier;
        if (spike && Boolean.TRUE.equals(redis.opsForValue().setIfAbsent(latchKey, "true", Duration.ofSeconds(windowSeconds)))) {
            logger.info("Trust signal {} fired for session {}", signalName(), session.id());
            return -20;
        }
        return 0;
    }
}
