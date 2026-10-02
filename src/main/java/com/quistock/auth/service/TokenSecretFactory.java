package com.quistock.auth.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import org.springframework.stereotype.Component;

@Component
public class TokenSecretFactory {
  private static final int TOKEN_BYTES = 32;
  private static final String TOKEN_PATTERN = "[A-Za-z0-9_-]{43}";
  private final SecureRandom secureRandom;

  public TokenSecretFactory(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  public String newToken() {
    byte[] tokenBytes = new byte[TOKEN_BYTES];
    secureRandom.nextBytes(tokenBytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
  }

  public String hash(String token) {
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256")
              .digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable.", exception);
    }
  }

  public boolean hasValidShape(String token) {
    return token != null && token.matches(TOKEN_PATTERN);
  }
}
