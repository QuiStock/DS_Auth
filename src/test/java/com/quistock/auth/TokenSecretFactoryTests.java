package com.quistock.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.quistock.auth.service.TokenSecretFactory;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class TokenSecretFactoryTests {
  private final TokenSecretFactory factory = new TokenSecretFactory(new SecureRandom());

  @Test
  void createsOpaqueTokensAndStoresOnlyTheirSha256Digest() {
    String token = factory.newToken();

    assertThat(token).matches("[A-Za-z0-9_-]{43}");
    assertThat(factory.hasValidShape(token)).isTrue();
    assertThat(factory.hash(token)).matches("[a-f0-9]{64}").isNotEqualTo(token);
  }

  @Test
  void rejectsMalformedTokenShapes() {
    assertThat(factory.hasValidShape(null)).isFalse();
    assertThat(factory.hasValidShape("not-a-token")).isFalse();
    assertThat(factory.hasValidShape("+".repeat(43))).isFalse();
  }
}
