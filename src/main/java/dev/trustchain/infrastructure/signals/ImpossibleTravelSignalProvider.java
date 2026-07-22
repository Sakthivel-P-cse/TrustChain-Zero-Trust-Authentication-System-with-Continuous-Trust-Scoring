package dev.trustchain.infrastructure.signals;

import dev.trustchain.domain.model.Session;
import dev.trustchain.domain.model.TrustScore;
import dev.trustchain.domain.policy.TrustSignalProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

public final class ImpossibleTravelSignalProvider implements TrustSignalProvider {
    private static final Logger logger = LoggerFactory.getLogger(ImpossibleTravelSignalProvider.class);
    private static final Map<String, Location> locations = Map.of(
            "203.0.113.10", new Location(40.7128, -74.0060),
            "198.51.100.20", new Location(51.5074, -0.1278),
            "192.0.2.30", new Location(35.6762, 139.6503));
    private final RedisTemplate<String, String> redis;

    public ImpossibleTravelSignalProvider(RedisTemplate<String, String> redis) {
        this.redis = redis;
    }

    @Override
    public String signalName() {
        return "impossible_travel";
    }

    @Override
    public int evaluate(Session session, HttpRequest request, TrustScore current) {
        String key = "signal:travel:" + session.id();
        Object storedIp = redis.opsForHash().get(key, "ip");
        Object storedAt = redis.opsForHash().get(key, "timestamp");
        String previousIp = storedIp == null ? session.ipAddress() : storedIp.toString();
        Instant previousAt = storedAt == null ? session.createdAt() : Instant.parse(storedAt.toString());
        redis.opsForHash().put(key, "ip", request.remoteAddress());
        redis.opsForHash().put(key, "timestamp", request.timestamp().toString());
        Location from = locations.get(previousIp);
        Location to = locations.get(request.remoteAddress());
        if (!previousIp.equals(request.remoteAddress()) && from != null && to != null
                && distance(from, to) > 500 && Duration.between(previousAt, request.timestamp()).toHours() < 6) {
            logger.info("Trust signal {} fired for session {}", signalName(), session.id());
            return -40;
        }
        return 0;
    }

    private double distance(Location first, Location second) {
        double latitude = Math.toRadians(second.latitude() - first.latitude());
        double longitude = Math.toRadians(second.longitude() - first.longitude());
        double value = Math.sin(latitude / 2) * Math.sin(latitude / 2)
                + Math.cos(Math.toRadians(first.latitude())) * Math.cos(Math.toRadians(second.latitude()))
                * Math.sin(longitude / 2) * Math.sin(longitude / 2);
        return 6371 * 2 * Math.atan2(Math.sqrt(value), Math.sqrt(1 - value));
    }

    private record Location(double latitude, double longitude) {
    }
}
