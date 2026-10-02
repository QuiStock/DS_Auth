package com.quistock.auth.service;

import com.quistock.auth.config.RateLimitSettings;
import com.quistock.auth.error.ApiExceptionFactory;
import com.quistock.auth.repository.MongoRateLimitStore;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

@Service
public class AuthRateLimitService {
  private static final int MINIMUM_HMAC_KEY_BYTES = 32;
  private static final int MINIMUM_LIMIT = 1;
  private static final long MINIMUM_WINDOW_SECONDS = 1;
  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private final MongoRateLimitStore store;
  private final RateLimitSettings settings;
  private final Clock clock;
  private final byte[] hmacKey;

  public AuthRateLimitService(
      MongoRateLimitStore store, RateLimitSettings settings, Clock authClock) {
    this.store = store;
    this.settings = settings;
    this.clock = authClock;
    byte[] configuredKey =
        settings.getHmacKey() == null
            ? new byte[0]
            : settings.getHmacKey().getBytes(StandardCharsets.UTF_8);
    if (configuredKey.length < MINIMUM_HMAC_KEY_BYTES) {
      throw new IllegalStateException("AUTH_RATE_LIMIT_HMAC_KEY must contain at least 32 bytes.");
    }
    this.hmacKey = configuredKey;
  }

  public void checkLoginRequest(String ipAddress) {
    check("login-ip", ipAddress, settings.getLoginIpLimit(), settings.getLoginIpWindow());
  }

  public void recordCredentialFailure(String ipAddress, String normalizedEmail) {
    check(
        "login-identity",
        ipAddress + "|" + normalizedEmail,
        settings.getLoginIdentityFailureLimit(),
        settings.getLoginIdentityFailureWindow());
  }

  public void checkRefreshRequest(String ipAddress) {
    check("refresh-ip", ipAddress, settings.getRefreshIpLimit(), settings.getRefreshIpWindow());
  }

  private void check(String category, String subject, int limit, Duration window) {
    if (limit < MINIMUM_LIMIT
        || window == null
        || window.isZero()
        || window.isNegative()
        || window.toSeconds() < MINIMUM_WINDOW_SECONDS) {
      throw new IllegalStateException("Rate-limit configuration must be positive.");
    }
    Instant now = clock.instant();
    long seconds = window.toSeconds();
    long windowStart = Math.floorDiv(now.getEpochSecond(), seconds) * seconds;
    Instant expiresAt = Instant.ofEpochSecond(windowStart + seconds);
    String bucketId = hmac(category + "|" + subject + "|" + windowStart);
    long count = store.increment(bucketId, expiresAt);
    if (count > limit) {
      long retryAfter = Math.max(1, Duration.between(now, expiresAt).toSeconds());
      throw ApiExceptionFactory.rateLimited(retryAfter);
    }
  }

  private String hmac(String value) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(new SecretKeySpec(hmacKey, HMAC_ALGORITHM));
      return java.util.HexFormat.of()
          .formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException("Unable to derive a rate-limit key.", exception);
    }
  }
}
