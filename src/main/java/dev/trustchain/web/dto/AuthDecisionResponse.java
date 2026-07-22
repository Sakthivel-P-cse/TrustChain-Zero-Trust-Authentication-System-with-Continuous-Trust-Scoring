package dev.trustchain.web.dto;

public record AuthDecisionResponse(boolean allowed, String reason, int trustScore) {
}
