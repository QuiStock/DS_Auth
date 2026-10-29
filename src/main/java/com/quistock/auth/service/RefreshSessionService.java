package com.quistock.auth.service;

import com.mongodb.MongoException;
import com.quistock.auth.config.JwtSettings;
import com.quistock.auth.dto.AuthTokens;
import com.quistock.auth.error.ApiExceptionFactory;
import com.quistock.auth.model.RefreshTokenDocument;
import com.quistock.auth.model.UserAccount;
import com.quistock.auth.repository.MongoRefreshTokenStore;
import com.quistock.auth.repository.UserAccountRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class RefreshSessionService {
  private static final String ACTIVE = "ACTIVE";
  private static final String CONSUMED = "CONSUMED";
  private final MongoRefreshTokenStore tokenStore;
  private final UserAccountRepository userRepository;
  private final JwtTokenIssuer tokenIssuer;
  private final TokenSecretFactory tokenFactory;
  private final Clock clock;
  private final TransactionTemplate transactionTemplate;

  public RefreshSessionService(
      MongoRefreshTokenStore tokenStore,
      UserAccountRepository userRepository,
      JwtTokenIssuer tokenIssuer,
      TokenSecretFactory tokenFactory,
      Clock authClock,
      @Qualifier("mongoTransactionTemplate") TransactionTemplate transactionTemplate) {
    this.tokenStore = tokenStore;
    this.userRepository = userRepository;
    this.tokenIssuer = tokenIssuer;
    this.tokenFactory = tokenFactory;
    this.clock = authClock;
    this.transactionTemplate = transactionTemplate;
  }

  public AuthTokens createSession(UserAccount account) {
    Instant now = clock.instant();
    String familyId = UUID.randomUUID().toString();
    String refreshToken = tokenFactory.newToken();
    String tokenId = UUID.randomUUID().toString();
    AuthTokens response = response(account, refreshToken);
    tokenStore.insert(
        new RefreshTokenDocument(
            tokenId,
            familyId,
            account.id(),
            tokenFactory.hash(refreshToken),
            ACTIVE,
            now,
            now.plus(JwtSettings.REFRESH_TOKEN_TTL),
            null,
            null,
            null));
    return response;
  }

  public AuthTokens refresh(String rawToken) {
    if (!tokenFactory.hasValidShape(rawToken)) {
      throw ApiExceptionFactory.invalidRefreshToken();
    }
    String tokenHash = tokenFactory.hash(rawToken);
    RotationResult result = rotateToken(tokenHash);
    if (result == null || result.response() == null) {
      revokeFamilyAfterReplay(tokenHash);
      throw ApiExceptionFactory.invalidRefreshToken();
    }
    return result.response();
  }

  @SuppressWarnings(
      "PMD.PreserveStackTrace") // A confirmed replay intentionally maps to generic 401.
  private RotationResult rotateToken(String tokenHash) {
    try {
      return transactionTemplate.execute(status -> rotate(tokenHash, clock.instant()));
    } catch (MongoException | DataAccessException | TransactionException exception) {
      if (revokeFamilyAfterReplay(tokenHash)) {
        throw ApiExceptionFactory.invalidRefreshToken();
      }
      throw ApiExceptionFactory.serviceUnavailable(exception);
    }
  }

  private boolean revokeFamilyAfterReplay(String tokenHash) {
    Boolean revoked =
        transactionTemplate.execute(
            status -> {
              Instant now = clock.instant();
              Optional<RefreshTokenDocument> current = tokenStore.findByTokenHash(tokenHash);
              if (current.isEmpty()
                  || !CONSUMED.equals(current.get().state())
                  || !current.get().expiresAt().isAfter(now)) {
                return false;
              }
              tokenStore.revokeFamily(current.get().familyId(), now);
              return true;
            });
    return Boolean.TRUE.equals(revoked);
  }

  public void logout(String rawToken) {
    if (!tokenFactory.hasValidShape(rawToken)) {
      return;
    }
    String tokenHash = tokenFactory.hash(rawToken);
    transactionTemplate.execute(
        status -> {
          Optional<RefreshTokenDocument> found = tokenStore.findByTokenHash(tokenHash);
          found.ifPresent(token -> tokenStore.revokeFamily(token.familyId(), clock.instant()));
          return null;
        });
  }

  private RotationResult rotate(String tokenHash, Instant now) {
    Optional<RefreshTokenDocument> found = tokenStore.findByTokenHash(tokenHash);
    if (found.isEmpty()) {
      return RotationResult.invalid();
    }
    RefreshTokenDocument current = found.get();

    if (isConsumedReplay(current, now)) {
      tokenStore.revokeFamily(current.familyId(), now);
      return RotationResult.invalid();
    }
    if (!isActiveAndUnexpired(current, now)) {
      return RotationResult.invalid();
    }

    Optional<UserAccount> account = userRepository.findById(current.userAccountId());
    if (account.filter(user -> ACTIVE.equals(user.status())).isEmpty()) {
      return RotationResult.invalid();
    }

    String successorToken = tokenFactory.newToken();
    String successorId = UUID.randomUUID().toString();
    AuthTokens response = response(account.orElseThrow(), successorToken);
    boolean consumed = tokenStore.consumeActive(current.id(), now, now, successorId);
    if (!consumed) {
      revokeChangedReplay(tokenHash, now);
      return RotationResult.invalid();
    }

    tokenStore.insert(
        new RefreshTokenDocument(
            successorId,
            current.familyId(),
            current.userAccountId(),
            tokenFactory.hash(successorToken),
            ACTIVE,
            now,
            now.plus(JwtSettings.REFRESH_TOKEN_TTL),
            null,
            null,
            null));
    return RotationResult.success(response);
  }

  private boolean isConsumedReplay(RefreshTokenDocument token, Instant now) {
    return CONSUMED.equals(token.state()) && token.expiresAt().isAfter(now);
  }

  private boolean isActiveAndUnexpired(RefreshTokenDocument token, Instant now) {
    return ACTIVE.equals(token.state()) && token.expiresAt().isAfter(now);
  }

  private void revokeChangedReplay(String tokenHash, Instant now) {
    Optional<RefreshTokenDocument> changed = tokenStore.findByTokenHash(tokenHash);
    changed
        .filter(token -> isConsumedReplay(token, now))
        .ifPresent(token -> tokenStore.revokeFamily(token.familyId(), now));
  }

  private AuthTokens response(UserAccount account, String refreshToken) {
    String accessToken = tokenIssuer.issue(account);
    return new AuthTokens(
        accessToken, refreshToken, tokenIssuer.accessTokenTtl(), JwtSettings.REFRESH_TOKEN_TTL);
  }

  private record RotationResult(AuthTokens response) {
    private static RotationResult success(AuthTokens response) {
      return new RotationResult(response);
    }

    private static RotationResult invalid() {
      return new RotationResult(null);
    }
  }
}
