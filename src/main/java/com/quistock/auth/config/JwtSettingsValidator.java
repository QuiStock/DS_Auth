package com.quistock.auth.config;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;

final class JwtSettingsValidator {
  private static final String IP_ADDRESS_LITERAL_PATTERN = "[0-9A-Fa-f:.]+";

  private JwtSettingsValidator() {}

  static void validate(JwtSettings settings) {
    if (hasMissingKeySettings(settings)) {
      throw new IllegalStateException("JWT issuer, audience, key id and key paths are required.");
    }
    if (!Duration.ofMinutes(5).equals(settings.getAccessTokenTtl())) {
      throw new IllegalStateException("JWT access token lifetime must be exactly five minutes.");
    }
    URI issuer = URI.create(settings.getIssuer());
    if (!isAllowedIssuer(issuer)) {
      throw new IllegalStateException("JWT issuer must use HTTPS except on the local machine.");
    }
  }

  private static boolean hasMissingKeySettings(JwtSettings settings) {
    return isBlank(settings.getIssuer())
        || isBlank(settings.getAudience())
        || isBlank(settings.getKeyId())
        || isBlank(settings.getPrivateKeyPath())
        || isBlank(settings.getPublicKeyPath());
  }

  private static boolean isAllowedIssuer(URI issuer) {
    String scheme = issuer.getScheme();
    String host = issuer.getHost();
    if (!issuer.isAbsolute() || host == null) {
      return false;
    }
    return "https".equalsIgnoreCase(scheme) || isLoopbackHttp(scheme, host);
  }

  private static boolean isLoopbackHttp(String scheme, String host) {
    return "http".equalsIgnoreCase(scheme)
        && ("localhost".equalsIgnoreCase(host) || isLoopbackAddress(host));
  }

  private static boolean isLoopbackAddress(String host) {
    if (!host.matches(IP_ADDRESS_LITERAL_PATTERN)) {
      return false;
    }
    try {
      return InetAddress.getByName(host).isLoopbackAddress();
    } catch (UnknownHostException exception) {
      return false;
    }
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }
}
