package com.quistock.auth.service;

import com.quistock.auth.dto.AuthTokens;
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
  private static final String MOBILE = "mobile";
  private static final String WEBSITE = "website";
  private static final String REGIONAL_MANAGER = "gerente regional";
  private static final String REPOSITOR = "repositor";
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

  public AuthTokens login(LoginRequest request, String ipAddress) {
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
    UserAccount account = found.orElseThrow();
    if (!canUsePlatform(account, request.platform())) {
      throw ApiException.forbiddenPlatform();
    }
    return refreshSessionService.createSession(account);
  }

  public AuthTokens refresh(String refreshToken, String ipAddress) {
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

  private boolean canUsePlatform(UserAccount account, String platform) {
    String roleName = normalizeRoleName(account.roleName());
    String roleCode = normalizeRoleName(account.roleCode());
    boolean regionalManager =
        REGIONAL_MANAGER.equals(roleName)
            || REGIONAL_MANAGER.equals(roleCode)
            || "regional manager".equals(roleName)
            || "regional manager".equals(roleCode);
    boolean repositor =
        REPOSITOR.equals(roleName) || REPOSITOR.equals(roleCode);
    return !(MOBILE.equals(platform) && regionalManager)
        && !(WEBSITE.equals(platform) && repositor);
  }

  private String normalizeRoleName(String value) {
    if (value == null) {
      return "";
    }
    return value.trim().toLowerCase(Locale.ROOT).replace('_', ' ').replace('-', ' ');
  }
}
