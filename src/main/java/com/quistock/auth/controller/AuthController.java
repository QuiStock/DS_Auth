package com.quistock.auth.controller;

import com.quistock.auth.config.CookieSettings;
import com.quistock.auth.dto.ApiError;
import com.quistock.auth.dto.AuthTokens;
import com.quistock.auth.dto.LoginRequest;
import com.quistock.auth.service.AuthenticationService;
import com.quistock.auth.service.TrustedClientIpResolver;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(
    name = "Autenticação",
    description = "Login público, rotação de sessão e logout por cookies HTTP-only.")
@ApiResponse(
    responseCode = "503",
    description = "Dependência de autenticação indisponível.",
    content = @Content(schema = @Schema(implementation = ApiError.class)))
@ApiResponse(
    responseCode = "500",
    description = "Erro interno.",
    content = @Content(schema = @Schema(implementation = ApiError.class)))
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
  @ApiResponse(
      responseCode = "400",
      description = "Request inválida.",
      content = @Content(schema = @Schema(implementation = ApiError.class)))
  @Operation(
      summary = "Autenticar usuário",
      description =
          "Não exige JWT. Valida email, senha BCrypt, conta ACTIVE e plataforma."
              + " Funcionário/Repositor não acessa website; Gerente Regional não acessa mobile.")
  @ApiResponse(
      responseCode = "200",
      description =
          "Corpo vazio. Emite dois cookies HTTP-only: access_token (Max-Age=300 segundos) e"
              + " refresh_token (Max-Age=1296000 segundos).",
      headers =
          @Header(
              name = "Set-Cookie",
              description =
                  "Dois headers Set-Cookie com Path, Secure, SameSite e Domain configurados."),
      content = @Content)
  @ApiResponse(
      responseCode = "401",
      description = "Email/senha inválidos ou conta inativa; resposta genérica.",
      content = @Content(schema = @Schema(implementation = ApiError.class)))
  @ApiResponse(
      responseCode = "403",
      description = "Perfil não permitido na plataforma (platform_not_allowed).",
      content = @Content(schema = @Schema(implementation = ApiError.class)))
  @ApiResponse(
      responseCode = "429",
      description = "Limite de tentativas excedido.",
      headers = @Header(name = "Retry-After", description = "Segundos até a próxima tentativa."),
      content = @Content(schema = @Schema(implementation = ApiError.class)))
  public ResponseEntity<Void> login(
      @Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
    AuthTokens tokens = authenticationService.login(request, clientIp(servletRequest));
    return withTokens(tokens);
  }

  @PostMapping("/refresh")
  @Operation(
      summary = "Renovar sessão",
      description =
          "Consome o refresh token e cria seu sucessor em transação MongoDB. Replay revoga a"
              + " família da sessão.",
      parameters =
          @Parameter(
              name = "X-CSRF-TOKEN",
              in = ParameterIn.HEADER,
              schema = @Schema(type = "string"),
              description =
                  "Token do JSON de GET /csrf; obrigatório quando refresh_token está presente."
                      + " Preserve AUTH-XSRF-TOKEN no cookie manager."))
  @SecurityRequirement(name = "refreshCookie")
  @ApiResponse(
      responseCode = "200",
      description = "Corpo vazio. Substitui os dois cookies, reiniciando seus Max-Age.",
      headers =
          @Header(
              name = "Set-Cookie",
              description = "Novos access_token e refresh_token HTTP-only."),
      content = @Content)
  @ApiResponse(
      responseCode = "401",
      description = "Refresh token ausente, inválido, expirado, revogado ou reutilizado.",
      content = @Content(schema = @Schema(implementation = ApiError.class)))
  @ApiResponse(
      responseCode = "403",
      description = "Cookie/header CSRF ausente ou inválido.",
      content = @Content)
  @ApiResponse(
      responseCode = "429",
      description = "Limite de renovações excedido.",
      headers = @Header(name = "Retry-After", description = "Segundos até a próxima tentativa."),
      content = @Content(schema = @Schema(implementation = ApiError.class)))
  public ResponseEntity<Void> refresh(HttpServletRequest servletRequest) {
    AuthTokens tokens =
        authenticationService.refresh(refreshToken(servletRequest), clientIp(servletRequest));
    return withTokens(tokens);
  }

  @PostMapping("/logout")
  @Operation(
      summary = "Encerrar sessão",
      description =
          "Revoga a família do refresh token. Idempotente para token ausente/desconhecido. Expira"
              + " os dois cookies com Max-Age=0; o access JWT já emitido pode ser aceito pela Core"
              + " até expirar.",
      parameters =
          @Parameter(
              name = "X-CSRF-TOKEN",
              in = ParameterIn.HEADER,
              schema = @Schema(type = "string"),
              description =
                  "Token de GET /csrf; obrigatório quando refresh_token está presente. Preserve"
                      + " também AUTH-XSRF-TOKEN."))
  @ApiResponse(
      responseCode = "204",
      description = "Corpo vazio; cookies de autenticação removidos.",
      headers =
          @Header(
              name = "Set-Cookie",
              description =
                  "access_token e refresh_token com Max-Age=0 e o mesmo escopo de emissão."),
      content = @Content)
  @ApiResponse(
      responseCode = "403",
      description = "Cookie/header CSRF ausente ou inválido.",
      content = @Content)
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
