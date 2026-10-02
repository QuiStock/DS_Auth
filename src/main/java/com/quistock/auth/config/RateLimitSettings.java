package com.quistock.auth.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.rate-limit")
// These mutable accessors are required by Spring Boot's configuration-properties binder.
@SuppressWarnings("PMD.DataClass")
public class RateLimitSettings {
  private String hmacKey;
  private int loginIpLimit = 10;
  private Duration loginIpWindow = Duration.ofMinutes(15);
  private int loginIdentityFailureLimit = 5;
  private Duration loginIdentityFailureWindow = Duration.ofMinutes(15);
  private int refreshIpLimit = 30;
  private Duration refreshIpWindow = Duration.ofMinutes(1);
  private List<String> trustedProxies = new ArrayList<>();

  public String getHmacKey() {
    return hmacKey;
  }

  public void setHmacKey(String hmacKey) {
    this.hmacKey = hmacKey;
  }

  public int getLoginIpLimit() {
    return loginIpLimit;
  }

  public void setLoginIpLimit(int loginIpLimit) {
    this.loginIpLimit = loginIpLimit;
  }

  public Duration getLoginIpWindow() {
    return loginIpWindow;
  }

  public void setLoginIpWindow(Duration loginIpWindow) {
    this.loginIpWindow = loginIpWindow;
  }

  public int getLoginIdentityFailureLimit() {
    return loginIdentityFailureLimit;
  }

  public void setLoginIdentityFailureLimit(int loginIdentityFailureLimit) {
    this.loginIdentityFailureLimit = loginIdentityFailureLimit;
  }

  public Duration getLoginIdentityFailureWindow() {
    return loginIdentityFailureWindow;
  }

  public void setLoginIdentityFailureWindow(Duration loginIdentityFailureWindow) {
    this.loginIdentityFailureWindow = loginIdentityFailureWindow;
  }

  public int getRefreshIpLimit() {
    return refreshIpLimit;
  }

  public void setRefreshIpLimit(int refreshIpLimit) {
    this.refreshIpLimit = refreshIpLimit;
  }

  public Duration getRefreshIpWindow() {
    return refreshIpWindow;
  }

  public void setRefreshIpWindow(Duration refreshIpWindow) {
    this.refreshIpWindow = refreshIpWindow;
  }

  public List<String> getTrustedProxies() {
    return trustedProxies;
  }

  public void setTrustedProxies(List<String> trustedProxies) {
    this.trustedProxies = trustedProxies;
  }
}
