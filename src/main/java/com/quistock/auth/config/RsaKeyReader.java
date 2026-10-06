package com.quistock.auth.config;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import org.springframework.security.converter.RsaKeyConverters;

final class RsaKeyReader {
  private RsaKeyReader() {}

  static RSAPrivateKey readPrivateKey(String path) throws IOException {
    try (InputStream input = Files.newInputStream(Path.of(path))) {
      return RsaKeyConverters.pkcs8().convert(input);
    }
  }

  static RSAPrivateKey readPrivateKey(JwtSettings settings) throws IOException {
    String encodedKey = settings.getPrivateKeyBase64();
    if (encodedKey == null || encodedKey.isBlank()) {
      return readPrivateKey(settings.getPrivateKeyPath());
    }
    byte[] pem = Base64.getDecoder().decode(encodedKey.trim());
    try (InputStream input = new ByteArrayInputStream(pem)) {
      return RsaKeyConverters.pkcs8().convert(input);
    }
  }

  static RSAPublicKey readPublicKey(String path) throws IOException {
    try (InputStream input = Files.newInputStream(Path.of(path))) {
      return RsaKeyConverters.x509().convert(input);
    }
  }

  static RSAPublicKey readPublicKey(JwtSettings settings) throws IOException {
    String encodedKey = settings.getPublicKeyBase64();
    if (encodedKey == null || encodedKey.isBlank()) {
      return readPublicKey(settings.getPublicKeyPath());
    }
    byte[] pem = Base64.getDecoder().decode(encodedKey.trim());
    try (InputStream input = new ByteArrayInputStream(pem)) {
      return RsaKeyConverters.x509().convert(input);
    }
  }
}
