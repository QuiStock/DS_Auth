package com.quistock.auth.controller;

import com.quistock.auth.dto.AuthResponse;
import com.quistock.auth.dto.LoginRequest;
import com.quistock.auth.dto.RefreshRequest;
import com.quistock.auth.service.AuthenticationService;
import com.quistock.auth.service.TrustedClientIpResolver;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {
  private final AuthenticationService authenticationService;
  private final TrustedClientIpResolver clientIpResolver;

  public AuthController(
      AuthenticationService authenticationService, TrustedClientIpResolver clientIpResolver) {
    this.authenticationService = authenticationService;
    this.clientIpResolver = clientIpResolver;
  }

  @PostMapping("/login")
  public ResponseEntity<AuthResponse> login(
      @Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
    AuthResponse response =
        authenticationService.login(request, clientIpResolver.resolve(servletRequest));
    return noStore(response);
  }

  @PostMapping("/refresh")
  public ResponseEntity<AuthResponse> refresh(
      @Valid @RequestBody RefreshRequest request, HttpServletRequest servletRequest) {
    AuthResponse response =
        authenticationService.refresh(
            request.refreshToken(), clientIpResolver.resolve(servletRequest));
    return noStore(response);
  }

  @PostMapping("/logout")
  public ResponseEntity<Void> logout(
      @Valid @RequestBody RefreshRequest request, HttpServletRequest servletRequest) {
    authenticationService.logout(request.refreshToken());
    return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
  }

  private ResponseEntity<AuthResponse> noStore(AuthResponse response) {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(response);
  }
}
