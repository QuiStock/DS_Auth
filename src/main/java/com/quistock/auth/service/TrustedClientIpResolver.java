package com.quistock.auth.service;

import com.quistock.auth.config.RateLimitSettings;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;

@Component
public class TrustedClientIpResolver {
  private static final int IPV4_OCTET_COUNT = 4;
  private static final int MAX_IPV4_OCTET_LENGTH = 3;
  private static final int MAX_IPV4_OCTET_VALUE = 255;
  private final List<IpAddressMatcher> trustedProxyMatchers;

  public TrustedClientIpResolver(RateLimitSettings settings) {
    this.trustedProxyMatchers =
        settings.getTrustedProxies().stream()
            .filter(proxy -> proxy != null && !proxy.isBlank())
            .map(IpAddressMatcher::new)
            .toList();
  }

  public String resolve(String remoteAddress, String forwardedFor) {
    if (remoteAddress == null || remoteAddress.isBlank()) {
      return "unknown";
    }
    String current = remoteAddress.trim();
    if (forwardedFor == null || forwardedFor.isBlank() || !isTrusted(current)) {
      return current;
    }

    List<String> forwardedAddresses = parseForwardedAddresses(forwardedFor);
    for (int index = forwardedAddresses.size() - 1; index >= 0 && isTrusted(current); index--) {
      current = forwardedAddresses.get(index);
    }
    return current;
  }

  private List<String> parseForwardedAddresses(String forwardedFor) {
    List<String> addresses = new ArrayList<>();
    for (String candidate : forwardedFor.split(",")) {
      String address = candidate.trim();
      if (isValidAddress(address)) {
        addresses.add(address);
      }
    }
    return addresses;
  }

  private boolean isTrusted(String address) {
    return trustedProxyMatchers.stream().anyMatch(matcher -> matcher.matches(address));
  }

  private boolean isValidAddress(String value) {
    if (value == null || value.isBlank() || value.contains("%")) {
      return false;
    }
    if (value.matches("[0-9.]+")) {
      return isValidIpv4(value);
    }
    return isValidIpv6(value);
  }

  private boolean isValidIpv4(String value) {
    String[] octets = value.split("\\.", -1);
    if (octets.length != IPV4_OCTET_COUNT) {
      return false;
    }
    for (String octet : octets) {
      if (octet.isEmpty() || octet.length() > MAX_IPV4_OCTET_LENGTH) {
        return false;
      }
      if (Integer.parseInt(octet) > MAX_IPV4_OCTET_VALUE) {
        return false;
      }
    }
    return true;
  }

  private boolean isValidIpv6(String value) {
    if (!value.matches("[0-9A-Fa-f:.]+") || !value.contains(":")) {
      return false;
    }
    try {
      return InetAddress.getByName(value) instanceof Inet6Address;
    } catch (UnknownHostException ignored) {
      return false;
    }
  }
}
