package com.quistock.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record LoginRequest(
    @Schema(description = "Email da conta provisionada no SQL.", example = "gerente@example.com")
        @NotBlank
        @Email
        @Size(max = 255)
        String email,
    @Schema(
            description = "Senha em texto para validação BCrypt; máximo de 72 bytes UTF-8.",
            format = "password",
            accessMode = Schema.AccessMode.WRITE_ONLY)
        @NotNull
        @Size(min = 1, max = 1024)
        String password,
    @Schema(
            description = "Aplicação de origem do login.",
            allowableValues = {"mobile", "website"},
            example = "website")
        @NotNull
        @Pattern(regexp = "mobile|website")
        String platform) {
  public LoginRequest {
    if (email != null) {
      email = email.trim();
    }
  }
}
