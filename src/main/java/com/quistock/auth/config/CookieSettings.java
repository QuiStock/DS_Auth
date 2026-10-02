package com.quistock.auth.config;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.cookies")
// Mutable accessors are required by Spring Boot's configuration-properties binder.
@SuppressWarnings("PMD.DataClass")
public class CookieSettings {
  private boolean secure = true;
  private String sameSite = "Lax";
  private String path = "/api";
  private String domain;

  @PostConstruct
  void validate() {
    if (path == null || !path.startsWith("/")) {
      throw new IllegalStateException("Authentication cookie path must start with '/'.");
    }
    if (!isValidSameSite(sameSite)) {
      throw new IllegalStateException(
          "Authentication cookie SameSite must be Strict, Lax, or None.");
    }
    if ("None".equalsIgnoreCase(sameSite) && !secure) {
      throw new IllegalStateException("SameSite=None authentication cookies require Secure.");
    }
  }

  private boolean isValidSameSite(String value) {
    return "Strict".equalsIgnoreCase(value)
        || "Lax".equalsIgnoreCase(value)
        || "None".equalsIgnoreCase(value);
  }

  public boolean isSecure() {
    return secure;
  }

  public void setSecure(boolean secure) {
    this.secure = secure;
  }

  public String getSameSite() {
    return sameSite;
  }

  public void setSameSite(String sameSite) {
    this.sameSite = sameSite;
  }

  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }

  public String getDomain() {
    return domain;
  }

  public void setDomain(String domain) {
    this.domain = domain;
  }
}
