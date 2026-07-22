package dev.trustchain.web.dto;

public record ServiceTokenRequest(String requestingServiceId, String targetServiceId, String delegatedUserId,
                                  String delegatedTenantId, String scopedAction) {
}
