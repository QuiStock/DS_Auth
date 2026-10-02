package com.quistock.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.password")
public class PasswordSettings {
  private int bcryptStrength = 12;

  public int getBcryptStrength() {
    return bcryptStrength;
  }

  public void setBcryptStrength(int bcryptStrength) {
    this.bcryptStrength = bcryptStrength;
  }
}
