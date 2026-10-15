package com.quistock.auth.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.responses.ApiResponse;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
    info =
        @Info(
            title = "QuiStock Auth API",
            version = "1.0",
            description =
                "Login e sessões com access JWT RS256 (5 minutos) e refresh token (15 dias). Tokens"
                    + " são enviados em cookies HTTP-only; login e refresh não retornam dados do"
                    + " usuário nem tokens no JSON. Refresh/logout com refresh_token exigem o"
                    + " cookie AUTH-XSRF-TOKEN e X-CSRF-TOKEN obtidos em GET /csrf. As rotas são"
                    + " relativas à raiz do serviço; prefixos de gateway são configurados no"
                    + " deploy."))
@SecurityScheme(
    name = "refreshCookie",
    type = SecuritySchemeType.APIKEY,
    in = SecuritySchemeIn.COOKIE,
    paramName = "refresh_token",
    description = "Cookie HTTP-only da sessão. Enviado pelo cookie manager.")
public class OpenApiConfig {
  @Bean
  OpenApiCustomizer healthResponses() {
    return api ->
        api.getPaths()
            .forEach(
                (path, item) -> {
                  if ("/health".equals(path) || path.startsWith("/health/")) {
                    item.readOperations()
                        .forEach(
                            operation ->
                                operation
                                    .getResponses()
                                    .addApiResponse(
                                        "503",
                                        new ApiResponse()
                                            .description(
                                                "Dependência indisponível ou timeout no health"
                                                    + " check.")));
                  }
                });
  }
}
