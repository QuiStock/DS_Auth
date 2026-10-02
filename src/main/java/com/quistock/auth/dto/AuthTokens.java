package com.quistock.auth.dto;

import java.time.Duration;

public record AuthTokens(
    String accessToken, String refreshToken, Duration accessTokenTtl, Duration refreshTokenTtl) {}
