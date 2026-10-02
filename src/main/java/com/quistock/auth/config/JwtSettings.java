package com.quistock.auth.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.jwt")
// These mutable accessors are required by Spring Boot's configuration-properties binder.
@SuppressWarnings("PMD.DataClass")
public class JwtSettings {
  private String issuer;
  private String audience;
  private String privateKeyPath;
  private String publicKeyPath;
  private String previousPublicKeys;
  private String keyId;
  private Duration accessTokenTtl = Duration.ofMinutes(5);

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public String getAudience() {
    return audience;
  }

  public void setAudience(String audience) {
    this.audience = audience;
  }

  public String getPrivateKeyPath() {
    return privateKeyPath;
  }

  public void setPrivateKeyPath(String privateKeyPath) {
    this.privateKeyPath = privateKeyPath;
  }

  public String getPublicKeyPath() {
    return publicKeyPath;
  }

  public void setPublicKeyPath(String publicKeyPath) {
    this.publicKeyPath = publicKeyPath;
  }

  public String getPreviousPublicKeys() {
    return previousPublicKeys;
  }

  public void setPreviousPublicKeys(String previousPublicKeys) {
    this.previousPublicKeys = previousPublicKeys;
  }

  public String getKeyId() {
    return keyId;
  }

  public void setKeyId(String keyId) {
    this.keyId = keyId;
  }

  public Duration getAccessTokenTtl() {
    return accessTokenTtl;
  }

  public void setAccessTokenTtl(Duration accessTokenTtl) {
    this.accessTokenTtl = accessTokenTtl;
  }
}
