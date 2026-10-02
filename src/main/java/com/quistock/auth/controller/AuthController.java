package com.quistock.auth.controller;

import com.quistock.auth.config.CookieSettings;
import com.quistock.auth.dto.AuthTokens;
import com.quistock.auth.dto.LoginRequest;
import com.quistock.auth.service.AuthenticationService;
import com.quistock.auth.service.TrustedClientIpResolver;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.time.Duration;
import java.util.Arrays;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
  private static final String X_FORWARDED_FOR = "X-Forwarded-For";
  private final AuthenticationService authenticationService;
  private final TrustedClientIpResolver clientIpResolver;
  private final CookieSettings cookieSettings;

  public AuthController(
      AuthenticationService authenticationService,
      TrustedClientIpResolver clientIpResolver,
      CookieSettings cookieSettings) {
    this.authenticationService = authenticationService;
    this.clientIpResolver = clientIpResolver;
    this.cookieSettings = cookieSettings;
  }

  @PostMapping("/login")
  public ResponseEntity<Void> login(
      @Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
    AuthTokens tokens = authenticationService.login(request, clientIp(servletRequest));
    return withTokens(tokens);
  }

  @PostMapping("/refresh")
  public ResponseEntity<Void> refresh(HttpServletRequest servletRequest) {
    AuthTokens tokens =
        authenticationService.refresh(refreshToken(servletRequest), clientIp(servletRequest));
    return withTokens(tokens);
  }

  @PostMapping("/logout")
  public ResponseEntity<Void> logout(HttpServletRequest servletRequest) {
    authenticationService.logout(refreshToken(servletRequest));
    return clearCookies();
  }

  private ResponseEntity<Void> withTokens(AuthTokens tokens) {
    return ResponseEntity.ok()
        .cacheControl(CacheControl.noStore())
        .header(
            HttpHeaders.SET_COOKIE,
            cookie("access_token", tokens.accessToken(), tokens.accessTokenTtl()))
        .header(
            HttpHeaders.SET_COOKIE,
            cookie("refresh_token", tokens.refreshToken(), tokens.refreshTokenTtl()))
        .build();
  }

  private ResponseEntity<Void> clearCookies() {
    return ResponseEntity.noContent()
        .cacheControl(CacheControl.noStore())
        .header(HttpHeaders.SET_COOKIE, cookie("access_token", "", Duration.ZERO))
        .header(HttpHeaders.SET_COOKIE, cookie("refresh_token", "", Duration.ZERO))
        .build();
  }

  private String cookie(String name, String value, Duration maxAge) {
    ResponseCookie.ResponseCookieBuilder cookie =
        ResponseCookie.from(name, value)
            .httpOnly(true)
            .secure(cookieSettings.isSecure())
            .path(cookieSettings.getPath())
            .sameSite(cookieSettings.getSameSite())
            .maxAge(maxAge);
    if (cookieSettings.getDomain() != null && !cookieSettings.getDomain().isBlank()) {
      cookie.domain(cookieSettings.getDomain());
    }
    return cookie.build().toString();
  }

  private String refreshToken(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return null;
    }
    return Arrays.stream(cookies)
        .filter(cookie -> "refresh_token".equals(cookie.getName()))
        .map(Cookie::getValue)
        .findFirst()
        .orElse(null);
  }

  private String clientIp(HttpServletRequest request) {
    return clientIpResolver.resolve(request.getRemoteAddr(), request.getHeader(X_FORWARDED_FOR));
  }
}
