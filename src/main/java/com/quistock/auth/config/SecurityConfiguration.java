package com.quistock.auth.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfiguration {
  private static final String REFRESH_TOKEN_COOKIE = "refresh_token";

  @Bean
  @SuppressWarnings("PMD.SignatureDeclareThrowsException")
  SecurityFilterChain authFilterChain(HttpSecurity http, CookieSettings settings) throws Exception {
    CookieCsrfTokenRepository csrf = new CookieCsrfTokenRepository();
    csrf.setCookieName("AUTH-XSRF-TOKEN");
    csrf.setHeaderName("X-CSRF-TOKEN");
    csrf.setCookieCustomizer(
        cookie -> {
          cookie
              .path(settings.getPath())
              .secure(settings.isSecure())
              .httpOnly(true)
              .sameSite(settings.getSameSite());
          if (settings.getDomain() != null && !settings.getDomain().isBlank()) {
            cookie.domain(settings.getDomain());
          }
        });
    return http.csrf(
            config ->
                config
                    .csrfTokenRepository(csrf)
                    .requireCsrfProtectionMatcher(SecurityConfiguration::requiresCsrf))
        .cors(Customizer.withDefaults())
        .httpBasic(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)
        .requestCache(AbstractHttpConfigurer::disable)
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            requests ->
                requests
                    .requestMatchers(HttpMethod.GET, "/health")
                    .permitAll()
                    .requestMatchers(HttpMethod.POST, "/login", "/logout", "/refresh")
                    .permitAll()
                    .requestMatchers(HttpMethod.GET, "/csrf", "/.well-known/jwks.json")
                    .permitAll()
                    .anyRequest()
                    .denyAll())
        .build();
  }

  private static boolean requiresCsrf(HttpServletRequest request) {
    String path = request.getServletPath();
    if (!"POST".equals(request.getMethod())
        || !("/refresh".equals(path) || "/logout".equals(path))) {
      return false;
    }
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
      for (Cookie cookie : cookies) {
        if (REFRESH_TOKEN_COOKIE.equals(cookie.getName())) {
          return true;
        }
      }
    }
    return false;
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource(
      @Value("${app.cors.allowed-origins:}") String origins) {
    CorsConfiguration cors = new CorsConfiguration();
    cors.setAllowedOrigins(
        Arrays.stream(origins.split(","))
            .map(String::trim)
            .filter(value -> !value.isEmpty())
            .toList());
    cors.setAllowCredentials(true);
    cors.validateAllowCredentials();
    cors.setAllowedMethods(List.of("GET", "HEAD", "POST", "OPTIONS"));
    cors.setAllowedHeaders(List.of("Content-Type", "X-CSRF-TOKEN"));
    cors.setMaxAge(3600L);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", cors);
    return source;
  }
}
