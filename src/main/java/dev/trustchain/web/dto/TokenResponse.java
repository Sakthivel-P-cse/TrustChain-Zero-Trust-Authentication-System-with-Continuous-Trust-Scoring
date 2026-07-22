package dev.trustchain.web.dto;

public record TokenResponse(String accessToken, String tokenType, long expiresIn, String refreshToken) {
}
