package com.quistock.auth.service;

import com.quistock.auth.config.CookieSettings;
import java.time.Duration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class AuthCookies {
  private final CookieSettings settings;

  public AuthCookies(CookieSettings settings) {
    this.settings = settings;
  }

  public String create(String name, String value, Duration maxAge) {
    var cookie =
        ResponseCookie.from(name, value)
            .httpOnly(true)
            .secure(settings.isSecure())
            .path(settings.getPath())
            .sameSite(settings.getSameSite())
            .maxAge(maxAge);
    if (settings.getDomain() != null && !settings.getDomain().isBlank())
      cookie.domain(settings.getDomain());
    return cookie.build().toString();
  }

  public void expire(HttpHeaders headers) {
    headers.add(HttpHeaders.SET_COOKIE, create("access_token", "", Duration.ZERO));
    headers.add(HttpHeaders.SET_COOKIE, create("refresh_token", "", Duration.ZERO));
  }
}
