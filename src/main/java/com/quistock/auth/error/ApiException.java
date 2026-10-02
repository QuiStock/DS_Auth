package com.quistock.auth.error;

import org.springframework.http.HttpStatus;

public final class ApiException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  private final HttpStatus httpStatus;
  private final String errorCode;
  private final String messageForClient;
  private final Long retryAfter;

  private ApiException(
      HttpStatus status, String code, String publicMessage, Long retryAfterSeconds) {
    super(publicMessage);
    this.httpStatus = status;
    this.errorCode = code;
    this.messageForClient = publicMessage;
    this.retryAfter = retryAfterSeconds;
  }

  private ApiException(
      HttpStatus status,
      String code,
      String publicMessage,
      Long retryAfterSeconds,
      Throwable cause) {
    super(publicMessage, cause);
    this.httpStatus = status;
    this.errorCode = code;
    this.messageForClient = publicMessage;
    this.retryAfter = retryAfterSeconds;
  }

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

  public HttpStatus status() {
    return httpStatus;
  }

  public String code() {
    return errorCode;
  }

  public String publicMessage() {
    return messageForClient;
  }

  public Long retryAfterSeconds() {
    return retryAfter;
  }
}
