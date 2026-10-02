package com.quistock.auth.service;

import com.quistock.auth.dto.AuthResponse;
import com.quistock.auth.dto.LoginRequest;
import com.quistock.auth.error.ApiException;
import com.quistock.auth.model.UserAccount;
import com.quistock.auth.repository.UserAccountRepository;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
  private static final int BCRYPT_MAX_PASSWORD_BYTES = 72;
  private static final String ACTIVE = "ACTIVE";
  private final UserAccountRepository userRepository;
  private final PasswordEncoder passwordEncoder;
  private final String dummyBcryptHash;
  private final AuthRateLimitService rateLimitService;
  private final RefreshSessionService refreshSessionService;

  public AuthenticationService(
      UserAccountRepository userRepository,
      PasswordEncoder passwordEncoder,
      String dummyBcryptHash,
      AuthRateLimitService rateLimitService,
      RefreshSessionService refreshSessionService) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
    this.dummyBcryptHash = dummyBcryptHash;
    this.rateLimitService = rateLimitService;
    this.refreshSessionService = refreshSessionService;
  }

  public AuthResponse login(LoginRequest request, String ipAddress) {
    byte[] passwordBytes = request.password().getBytes(StandardCharsets.UTF_8);
    if (passwordBytes.length > BCRYPT_MAX_PASSWORD_BYTES) {
      throw ApiException.invalidRequest();
    }

    String normalizedEmail = request.email().toLowerCase(Locale.ROOT);
    rateLimitService.checkLoginRequest(ipAddress);
    Optional<UserAccount> found = userRepository.findByNormalizedEmail(normalizedEmail);
    String storedHash = found.map(UserAccount::passwordHash).orElse(dummyBcryptHash);
    boolean passwordMatches = passwordMatches(request.password(), storedHash);
    boolean active = found.map(account -> ACTIVE.equals(account.status())).orElse(false);

    if (!active || !passwordMatches) {
      rateLimitService.recordCredentialFailure(ipAddress, normalizedEmail);
      throw ApiException.invalidCredentials();
    }
    return refreshSessionService.createSession(found.orElseThrow());
  }

  public AuthResponse refresh(String refreshToken, String ipAddress) {
    rateLimitService.checkRefreshRequest(ipAddress);
    return refreshSessionService.refresh(refreshToken);
  }

  public void logout(String refreshToken) {
    refreshSessionService.logout(refreshToken);
  }

  private boolean passwordMatches(String password, String storedHash) {
    try {
      return passwordEncoder.matches(password, storedHash);
    } catch (IllegalArgumentException exception) {
      passwordEncoder.matches(password, dummyBcryptHash);
      return false;
    }
  }
}
