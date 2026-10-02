package com.quistock.auth.service;

import com.quistock.auth.config.JwtKeyMaterial;
import com.quistock.auth.config.JwtSettings;
import com.quistock.auth.model.UserAccount;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenIssuer {
  private final JwtEncoder jwtEncoder;
  private final JwtSettings settings;
  private final JwtKeyMaterial keyMaterial;
  private final Clock clock;

  public JwtTokenIssuer(
      JwtEncoder jwtEncoder, JwtSettings settings, JwtKeyMaterial keyMaterial, Clock authClock) {
    this.jwtEncoder = jwtEncoder;
    this.settings = settings;
    this.keyMaterial = keyMaterial;
    this.clock = authClock;
  }

  public String issue(UserAccount account) {
    if (account.id() <= 0 || account.email() == null || account.email().isBlank()) {
      throw new IllegalStateException("A positive user id and email are required to issue a JWT.");
    }
    Instant issuedAt = clock.instant();
    JwtClaimsSet claims =
        JwtClaimsSet.builder()
            .issuer(settings.getIssuer())
            .audience(List.of(settings.getAudience()))
            .subject(Long.toString(account.id()))
            .claim("email", account.email())
            .issuedAt(issuedAt)
            .expiresAt(issuedAt.plus(settings.getAccessTokenTtl()))
            .id(UUID.randomUUID().toString())
            .build();
    JwsHeader header =
        JwsHeader.with(SignatureAlgorithm.RS256)
            .keyId(keyMaterial.activeSigningKey().getKeyID())
            .build();
    return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
  }

  public Duration accessTokenTtl() {
    return settings.getAccessTokenTtl();
  }
}
