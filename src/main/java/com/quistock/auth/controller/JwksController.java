package com.quistock.auth.controller;

import com.nimbusds.jose.jwk.JWKSet;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Duration;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "Chaves públicas")
public class JwksController {
  private final JWKSet jwkSet;

  public JwksController(JWKSet jwkSet) {
    this.jwkSet = jwkSet;
  }

  @GetMapping(value = "/.well-known/jwks.json", produces = "application/json")
  @Operation(
      summary = "Consultar JWKS público",
      description =
          "Chaves públicas RSA para verificar JWT RS256. Inclui a chave ativa e anteriores"
              + " configuradas. Não expõe chave privada nem tokens. Cache público de 5 minutos.")
  public ResponseEntity<Map<String, Object>> jwks() {
    return ResponseEntity.ok()
        .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
        .body(jwkSet.toJSONObject());
  }
}
