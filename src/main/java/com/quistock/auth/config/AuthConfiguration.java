package com.quistock.auth.config;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.UUID;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableConfigurationProperties({
  JwtSettings.class,
  PasswordSettings.class,
  RateLimitSettings.class,
  CookieSettings.class
})
public class AuthConfiguration {
  @Bean
  Clock authClock() {
    return Clock.systemUTC();
  }

  @Bean
  SecureRandom secureRandom() {
    return new SecureRandom();
  }

  @Bean
  PasswordEncoder passwordEncoder(PasswordSettings settings) {
    int strength = settings.getBcryptStrength();
    if (strength < 4 || strength > 16) {
      throw new IllegalStateException("BCrypt strength must be between 4 and 16.");
    }
    return new BCryptPasswordEncoder(strength);
  }

  @Bean
  String dummyBcryptHash(PasswordEncoder passwordEncoder) {
    return passwordEncoder.encode(UUID.randomUUID().toString());
  }
}
