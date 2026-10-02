package com.quistock.auth.error;

import com.mongodb.MongoException;
import com.quistock.auth.dto.ApiError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.transaction.TransactionException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {
  private static final Logger LOGGER = LoggerFactory.getLogger(ApiExceptionHandler.class);

  @ExceptionHandler(ApiException.class)
  ResponseEntity<ApiError> handleApiException(ApiException exception) {
    HttpHeaders headers = noStoreHeaders();
    if (exception.retryAfterSeconds() != null) {
      headers.set(HttpHeaders.RETRY_AFTER, Long.toString(exception.retryAfterSeconds()));
    }
    return new ResponseEntity<>(
        new ApiError(exception.code(), exception.publicMessage()), headers, exception.status());
  }

  @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
  ResponseEntity<ApiError> handleInvalidRequest(Exception ignored) {
    return ResponseEntity.badRequest()
        .headers(noStoreHeaders())
        .body(new ApiError("invalid_request", "Requisição inválida."));
  }

  @ExceptionHandler({DataAccessException.class, MongoException.class, TransactionException.class})
  ResponseEntity<ApiError> handleDatabaseFailure(Exception ignored) {
    return ResponseEntity.status(503)
        .headers(noStoreHeaders())
        .body(new ApiError("service_unavailable", "Serviço temporariamente indisponível."));
  }

  @ExceptionHandler(Exception.class)
  ResponseEntity<ApiError> handleUnexpected(Exception exception) {
    if (LOGGER.isErrorEnabled()) {
      LOGGER.error(
          "Unhandled request failure ({}); response status set to 500.",
          exception.getClass().getSimpleName());
    }
    return ResponseEntity.internalServerError()
        .headers(noStoreHeaders())
        .body(new ApiError("internal_error", "Erro interno."));
  }

  private HttpHeaders noStoreHeaders() {
    HttpHeaders headers = new HttpHeaders();
    headers.setCacheControl(CacheControl.noStore());
    return headers;
  }
}
