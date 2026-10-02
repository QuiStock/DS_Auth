package com.quistock.auth.error;

import org.springframework.http.HttpStatus;

public final class ApiException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  private final HttpStatus httpStatus;
  private final String errorCode;
  private final String messageForClient;
  private final Long retryAfter;

  ApiException(HttpStatus status, String code, String publicMessage, Long retryAfterSeconds) {
    super(publicMessage);
    this.httpStatus = status;
    this.errorCode = code;
    this.messageForClient = publicMessage;
    this.retryAfter = retryAfterSeconds;
  }

  ApiException(
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
