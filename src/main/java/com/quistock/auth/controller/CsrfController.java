package com.quistock.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "CSRF")
public class CsrfController {
  @GetMapping("/csrf")
  @Operation(
      summary = "Obter token CSRF da Auth",
      description =
          "Público. Retorna headerName/token, Cache-Control: no-store e cookie HTTP-only"
              + " AUTH-XSRF-TOKEN. Envie o token em X-CSRF-TOKEN no refresh/logout com cookie. Não"
              + " retorna JWT nem refresh token.")
  public ResponseEntity<CsrfResponse> token(@Parameter(hidden = true) CsrfToken csrf) {
    return ResponseEntity.ok()
        .cacheControl(CacheControl.noStore())
        .body(new CsrfResponse(csrf.getHeaderName(), csrf.getToken()));
  }

  public record CsrfResponse(String headerName, String token) {}
}
