package com.quistock.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.quistock.auth.config.RateLimitSettings;
import com.quistock.auth.service.TrustedClientIpResolver;
import java.util.List;
import org.junit.jupiter.api.Test;

class TrustedClientIpResolverTests {
  @Test
  void ignoresForwardedAddressesFromUntrustedPeers() {
    TrustedClientIpResolver resolver = resolver(List.of("10.0.0.0/8"));

    assertThat(resolver.resolve("192.0.2.4", "203.0.113.5")).isEqualTo("192.0.2.4");
  }

  @Test
  void walksTrustedProxyChainFromTheNearestProxyToClient() {
    TrustedClientIpResolver resolver = resolver(List.of("10.0.0.0/8"));

    String clientIp = resolver.resolve("10.0.0.2", "198.51.100.8, 10.0.0.1");

    assertThat(clientIp).isEqualTo("198.51.100.8");
  }

  @Test
  void ignoresInvalidForwardedAddressesAndBlankProxyEntries() {
    TrustedClientIpResolver resolver = resolver(List.of("", "10.0.0.0/8"));

    assertThat(resolver.resolve("10.0.0.2", "attacker.example")).isEqualTo("10.0.0.2");
    assertThat(resolver.resolve(null, "203.0.113.5")).isEqualTo("unknown");
  }

  private TrustedClientIpResolver resolver(List<String> trustedProxies) {
    RateLimitSettings settings = new RateLimitSettings();
    settings.setTrustedProxies(trustedProxies);
    return new TrustedClientIpResolver(settings);
  }
}
