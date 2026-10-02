package com.quistock.auth.controller;

import com.nimbusds.jose.jwk.JWKSet;
import java.time.Duration;
import java.util.Map;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksController {
  private final JWKSet jwkSet;

  public JwksController(JWKSet jwkSet) {
    this.jwkSet = jwkSet;
  }

  @GetMapping(value = "/.well-known/jwks.json", produces = "application/json")
  public ResponseEntity<Map<String, Object>> jwks() {
    return ResponseEntity.ok()
        .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
        .body(jwkSet.toJSONObject());
  }
}
