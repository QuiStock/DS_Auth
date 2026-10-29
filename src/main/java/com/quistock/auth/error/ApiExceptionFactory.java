package com.quistock.auth.error;

import org.springframework.http.HttpStatus;

public final class ApiExceptionFactory {
  private ApiExceptionFactory() {}

  public static ApiException invalidRequest() {
    return new ApiException(
        HttpStatus.BAD_REQUEST, "invalid_request", "Requisição inválida.", null);
  }

  public static ApiException invalidCredentials() {
    return new ApiException(
        HttpStatus.UNAUTHORIZED, "invalid_credentials", "Email ou senha inválidos.", null);
  }

  public static ApiException forbiddenPlatform() {
    return new ApiException(
        HttpStatus.FORBIDDEN,
        "platform_not_allowed",
        "Este perfil não pode acessar esta plataforma.",
        null);
  }

  public static ApiException invalidRefreshToken() {
    return new ApiException(
        HttpStatus.UNAUTHORIZED, "invalid_refresh_token", "Refresh token inválido.", null);
  }

  public static ApiException rateLimited(long retryAfterSeconds) {
    return new ApiException(
        HttpStatus.TOO_MANY_REQUESTS,
        "rate_limited",
        "Limite de tentativas atingido.",
        Math.max(1, retryAfterSeconds));
  }

  public static ApiException serviceUnavailable() {
    return new ApiException(
        HttpStatus.SERVICE_UNAVAILABLE,
        "service_unavailable",
        "Serviço temporariamente indisponível.",
        null);
  }

  public static ApiException serviceUnavailable(Throwable cause) {
    return new ApiException(
        HttpStatus.SERVICE_UNAVAILABLE,
        "service_unavailable",
        "Serviço temporariamente indisponível.",
        null,
        cause);
  }
}
