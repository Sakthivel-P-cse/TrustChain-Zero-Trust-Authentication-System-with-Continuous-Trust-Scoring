package dev.trustchain.domain.model;

public record ServiceIdentity(String serviceId, String tenantId, String certificateFingerprint) {
}
