package com.quistock.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record LoginRequest(
    @NotBlank @Email @Size(max = 255) String email,
    @NotNull @Size(min = 1, max = 1024) String password,
    @NotNull @Pattern(regexp = "mobile|website") String platform) {
  public LoginRequest {
    if (email != null) {
      email = email.trim();
    }
  }
}
