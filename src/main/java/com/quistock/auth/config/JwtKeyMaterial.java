package com.quistock.auth.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.stereotype.Component;

@Component
public class JwtKeyMaterial {
  private static final int MIN_RSA_KEY_BITS = 2048;
  private static final int KEY_ENTRY_PART_COUNT = 2;
  private final RSAKey signingKeyMaterial;
  private final JWKSet publishedPublicKeys;

  public JwtKeyMaterial(JwtSettings settings) {
    try {
      JwtSettingsValidator.validate(settings);
      RSAPrivateKey privateKey = readPrivateKey(settings.getPrivateKeyPath());
      RSAPublicKey publicKey = readPublicKey(settings.getPublicKeyPath());
      validateKeyPair(privateKey, publicKey);

      this.signingKeyMaterial =
          new RSAKey.Builder(publicKey)
              .privateKey(privateKey)
              .keyID(settings.getKeyId())
              .algorithm(JWSAlgorithm.RS256)
              .keyUse(KeyUse.SIGNATURE)
              .build();
      this.publishedPublicKeys = new JWKSet(loadPublicKeys(settings, publicKey));
    } catch (IOException
        | GeneralSecurityException
        | JOSEException
        | IllegalArgumentException exception) {
      throw new IllegalStateException("JWT RSA key configuration is invalid.", exception);
    }
  }

  public RSAKey activeSigningKey() {
    return signingKeyMaterial;
  }

  public JWKSet publicJwkSet() {
    return publishedPublicKeys;
  }

  private List<RSAKey> loadPublicKeys(JwtSettings settings, RSAPublicKey activeKey)
      throws IOException, JOSEException {
    List<RSAKey> keys = new ArrayList<>();
    Set<String> keyIds = new HashSet<>();
    keyIds.add(settings.getKeyId());
    keys.add(
        new RSAKey.Builder(activeKey)
            .keyID(settings.getKeyId())
            .algorithm(JWSAlgorithm.RS256)
            .keyUse(KeyUse.SIGNATURE)
            .build());

    String previous = settings.getPreviousPublicKeys();
    if (previous == null || previous.isBlank()) {
      return keys;
    }

    addPreviousPublicKeys(previous, keys, keyIds);
    return keys;
  }

  private void addPreviousPublicKeys(String previous, List<RSAKey> keys, Set<String> keyIds)
      throws IOException, JOSEException {
    for (String entry : previous.split(";")) {
      String[] parts = entry.trim().split("=", 2);
      if (parts.length != KEY_ENTRY_PART_COUNT || parts[0].isBlank() || parts[1].isBlank()) {
        throw new IllegalStateException(
            "Previous public keys must use kid=path entries separated by ';'.");
      }
      if (!keyIds.add(parts[0])) {
        throw new IllegalStateException("JWT key ids must be unique.");
      }
      RSAPublicKey previousKey = readPublicKey(parts[1]);
      validatePublicKeySize(previousKey);
      keys.add(buildPublicKey(previousKey, parts[0]));
    }
  }

  private RSAKey buildPublicKey(RSAPublicKey publicKey, String keyId) throws JOSEException {
    return new RSAKey.Builder(publicKey)
        .keyID(keyId)
        .algorithm(JWSAlgorithm.RS256)
        .keyUse(KeyUse.SIGNATURE)
        .build();
  }

  private void validatePublicKeySize(RSAPublicKey publicKey) {
    if (publicKey.getModulus().bitLength() < MIN_RSA_KEY_BITS) {
      throw new IllegalStateException("RSA keys must be at least 2048 bits.");
    }
  }

  private RSAPrivateKey readPrivateKey(String path) throws IOException {
    try (InputStream input = Files.newInputStream(Path.of(path))) {
      return RsaKeyConverters.pkcs8().convert(input);
    }
  }

  private RSAPublicKey readPublicKey(String path) throws IOException {
    try (InputStream input = Files.newInputStream(Path.of(path))) {
      return RsaKeyConverters.x509().convert(input);
    }
  }

  private void validateKeyPair(RSAPrivateKey privateKey, RSAPublicKey publicKey)
      throws GeneralSecurityException {
    validatePublicKeySize(publicKey);
    if (privateKey.getModulus().bitLength() < MIN_RSA_KEY_BITS) {
      throw new IllegalStateException("RSA keys must be at least 2048 bits.");
    }
    byte[] challenge =
        UUID.randomUUID().toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    Signature signer = Signature.getInstance("SHA256withRSA");
    signer.initSign(privateKey);
    signer.update(challenge);
    byte[] signed = signer.sign();

    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(publicKey);
    verifier.update(challenge);
    if (!verifier.verify(signed)) {
      throw new IllegalStateException("JWT public and private keys do not match.");
    }
  }
}
