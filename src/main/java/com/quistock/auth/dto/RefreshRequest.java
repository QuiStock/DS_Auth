package com.quistock.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshRequest(
    @JsonProperty("refresh_token") @NotBlank @Size(max = 128) String refreshToken) {}
