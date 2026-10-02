package com.quistock.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
public class JwtConfiguration {
  @Bean
  JwtEncoder jwtEncoder(JwtKeyMaterial keyMaterial) {
    return new NimbusJwtEncoder(
        new ImmutableJWKSet<SecurityContext>(new JWKSet(keyMaterial.activeSigningKey())));
  }

  @Bean
  JWKSet publicJwkSet(JwtKeyMaterial keyMaterial) {
    return keyMaterial.publicJwkSet();
  }
}
