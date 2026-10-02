package com.quistock.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.quistock.auth.config.RateLimitSettings;
import com.quistock.auth.model.RateLimitCounter;
import com.quistock.auth.model.RefreshTokenDocument;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.mongodb.MongoDBContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;

@Testcontainers
@AutoConfigureTestRestTemplate
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = "server.servlet.context-path=/api")
class DsAuthApplicationTests {
  private static final String PASSWORD = "a-correct-test-password";
  private static final String ACTIVE_EMAIL = "active@example.com";
  private static final KeyFiles KEY_FILES = createKeyFiles();

  @Container
  private static final PostgreSQLContainer POSTGRES =
      new PostgreSQLContainer("postgres:16-alpine").withInitScripts("db/schema.sql");

  @Container
  private static final MongoDBContainer MONGO = new MongoDBContainer("mongo:8.0").withReplicaSet();

  @LocalServerPort private int port;

  @Autowired private TestRestTemplate restTemplate;
  @Autowired private JdbcTemplate jdbcTemplate;
  @Autowired private MongoTemplate mongoTemplate;
  @Autowired private PasswordEncoder passwordEncoder;
  @Autowired private RateLimitSettings rateLimitSettings;

  @DynamicPropertySource
  static void registerTestProperties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
    registry.add("spring.datasource.username", POSTGRES::getUsername);
    registry.add("spring.datasource.password", POSTGRES::getPassword);
    registry.add("spring.datasource.hikari.read-only", () -> false);
    registry.add("spring.mongodb.uri", MONGO::getReplicaSetUrl);
    registry.add("spring.mongodb.database", () -> "quistock_auth_test");
    registry.add("auth.jwt.private-key-path", () -> KEY_FILES.privateKey().toString());
    registry.add("auth.jwt.public-key-path", () -> KEY_FILES.publicKey().toString());
  }

  @BeforeEach
  void prepareDatabase() {
    mongoTemplate.remove(new Query(), RefreshTokenDocument.class);
    mongoTemplate.remove(new Query(), RateLimitCounter.class);
    jdbcTemplate.update("DELETE FROM user_account");
    jdbcTemplate.update(
        "INSERT INTO role (id, code, name) VALUES (1, 'REPOSITOR', 'Repositor') "
            + "ON CONFLICT (id) DO NOTHING");
    jdbcTemplate.update(
        "INSERT INTO role (id, code, name) VALUES (2, 'GERENTE_REGIONAL', 'Gerente Regional') "
            + "ON CONFLICT (id) DO NOTHING");
    String passwordHash = passwordEncoder.encode(PASSWORD);
    jdbcTemplate.update(
        "INSERT INTO user_account (id, role_id, email, status, password_hash) "
            + "VALUES (?, 1, ?, 'ACTIVE', ?)",
        101L,
        ACTIVE_EMAIL,
        passwordHash);
    jdbcTemplate.update(
        "INSERT INTO user_account (id, role_id, email, status, password_hash) "
            + "VALUES (?, 1, ?, 'INACTIVE', ?)",
        202L,
        "inactive@example.com",
        passwordHash);
  }

  @Test
  void loginIssuesShortLivedJwtAndPublicJwksVerifiesIt() throws Exception {
    ResponseEntity<JsonNode> response = login(ACTIVE_EMAIL, PASSWORD);

    assertEquals(HttpStatus.OK, response.getStatusCode());
    assertThat(response.getHeaders().getCacheControl()).contains("no-store");
    assertThat(response.getBody()).isNull();
    String accessToken = cookieValue(response, "access_token");
    String refreshToken = cookieValue(response, "refresh_token");
    assertThat(setCookie(response, "access_token"))
        .contains("HttpOnly", "Secure", "Path=/api", "SameSite=Lax", "Max-Age=300");
    assertThat(setCookie(response, "refresh_token"))
        .contains("HttpOnly", "Secure", "Path=/api", "SameSite=Lax", "Max-Age=1296000");
    RefreshTokenDocument storedToken = mongoTemplate.findAll(RefreshTokenDocument.class).getFirst();
    assertThat(storedToken.tokenHash()).isEqualTo(sha256(refreshToken));
    assertThat(storedToken.tokenHash()).isNotEqualTo(refreshToken);

    SignedJWT token = SignedJWT.parse(accessToken);
    assertThat(token.getJWTClaimsSet().getSubject()).isEqualTo("101");
    assertThat(token.getJWTClaimsSet().getStringClaim("email")).isEqualTo(ACTIVE_EMAIL);
    assertThat(token.getJWTClaimsSet().getIssuer()).isEqualTo("https://auth.test.example");
    assertThat(token.getJWTClaimsSet().getAudience()).containsExactly("quistock-api");
    assertThat(
            token.getJWTClaimsSet().getExpirationTime().getTime()
                - token.getJWTClaimsSet().getIssueTime().getTime())
        .isEqualTo(300_000);
    assertThat(token.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
    assertThat(token.getHeader().getKeyID()).isEqualTo("test-active");

    ResponseEntity<String> jwksResponse =
        restTemplate.getForEntity(baseUrl() + "/.well-known/jwks.json", String.class);
    assertEquals(HttpStatus.OK, jwksResponse.getStatusCode());
    assertThat(jwksResponse.getHeaders().getCacheControl()).contains("public");
    JWKSet jwks = JWKSet.parse(jwksResponse.getBody());
    assertThat(jwks.getKeys()).hasSize(1);
    RSAKey publicKey = (RSAKey) jwks.getKeyByKeyId("test-active");
    assertThat(publicKey.isPrivate()).isFalse();
    JWSVerifier verifier = new RSASSAVerifier(publicKey.toRSAPublicKey());
    assertTrue(token.verify(verifier));
  }

  @Test
  void unknownWrongAndInactiveCredentialsReturnTheSameUnauthorizedBody() {
    ResponseEntity<JsonNode> unknown = login("unknown@example.com", PASSWORD);
    ResponseEntity<JsonNode> incorrect = login(ACTIVE_EMAIL, "wrong-password");
    ResponseEntity<JsonNode> inactive = login("inactive@example.com", PASSWORD);

    assertEquals(HttpStatus.UNAUTHORIZED, unknown.getStatusCode());
    assertEquals(HttpStatus.UNAUTHORIZED, incorrect.getStatusCode());
    assertEquals(HttpStatus.UNAUTHORIZED, inactive.getStatusCode());
    assertThat(unknown.getBody()).isEqualTo(incorrect.getBody()).isEqualTo(inactive.getBody());
    assertThat(unknown.getBody().path("code").asText()).isEqualTo("invalid_credentials");
  }

  @Test
  void loginNormalizesEmailAndEnforcesRolePlatformRestrictions() {
    ResponseEntity<JsonNode> response = login("  ACTIVE@EXAMPLE.COM  ", PASSWORD);

    assertEquals(HttpStatus.OK, response.getStatusCode());
    assertThat(response.getBody()).isNull();
    jdbcTemplate.update(
        "INSERT INTO user_account (id, role_id, email, status, password_hash) "
            + "VALUES (?, 2, ?, 'ACTIVE', ?)",
        303L,
        "manager@example.com",
        passwordEncoder.encode(PASSWORD));

    ResponseEntity<JsonNode> managerMobile = login("manager@example.com", PASSWORD, "mobile");
    ResponseEntity<JsonNode> managerWebsite = login("manager@example.com", PASSWORD, "website");
    ResponseEntity<JsonNode> repositorWebsite = login(ACTIVE_EMAIL, PASSWORD, "website");

    assertEquals(HttpStatus.FORBIDDEN, managerMobile.getStatusCode());
    assertThat(managerMobile.getBody().path("code").asText()).isEqualTo("platform_not_allowed");
    assertEquals(HttpStatus.OK, managerWebsite.getStatusCode());
    assertThat(managerWebsite.getBody()).isNull();
    assertEquals(HttpStatus.FORBIDDEN, repositorWebsite.getStatusCode());
    assertThat(repositorWebsite.getBody().path("code").asText()).isEqualTo("platform_not_allowed");
  }

  @Test
  void malformedLoginAndRefreshPayloadsReturnUniformBadRequest() {
    ResponseEntity<JsonNode> malformedEmail =
        restTemplate.postForEntity(
            baseUrl() + "/auth/login",
            Map.of("email", "not-an-email", "password", PASSWORD, "platform", "mobile"),
            JsonNode.class);
    ResponseEntity<JsonNode> missingPassword =
        restTemplate.postForEntity(
            baseUrl() + "/auth/login",
            Map.of("email", ACTIVE_EMAIL, "platform", "mobile"),
            JsonNode.class);
    ResponseEntity<JsonNode> invalidPlatform =
        restTemplate.postForEntity(
            baseUrl() + "/auth/login",
            Map.of("email", ACTIVE_EMAIL, "password", PASSWORD, "platform", "desktop"),
            JsonNode.class);
    ResponseEntity<JsonNode> missingRefreshCookie =
        restTemplate.postForEntity(baseUrl() + "/auth/refresh", Map.of(), JsonNode.class);
    ResponseEntity<JsonNode> oversizedPassword = login(ACTIVE_EMAIL, "á".repeat(37));

    assertEquals(HttpStatus.BAD_REQUEST, malformedEmail.getStatusCode());
    assertEquals(HttpStatus.BAD_REQUEST, missingPassword.getStatusCode());
    assertEquals(HttpStatus.BAD_REQUEST, invalidPlatform.getStatusCode());
    assertEquals(HttpStatus.UNAUTHORIZED, missingRefreshCookie.getStatusCode());
    assertEquals(HttpStatus.BAD_REQUEST, oversizedPassword.getStatusCode());
    assertThat(malformedEmail.getBody().path("code").asText()).isEqualTo("invalid_request");
    assertThat(missingPassword.getBody()).isEqualTo(malformedEmail.getBody());
    assertThat(invalidPlatform.getBody()).isEqualTo(malformedEmail.getBody());
    assertThat(missingRefreshCookie.getBody().path("code").asText())
        .isEqualTo("invalid_refresh_token");
    assertThat(oversizedPassword.getBody()).isEqualTo(malformedEmail.getBody());
  }

  @Test
  void refreshRotatesTokenAndReplayRevokesTheWholeFamily() {
    String original = cookieValue(login(ACTIVE_EMAIL, PASSWORD), "refresh_token");
    ResponseEntity<JsonNode> rotated = refresh(original);
    String successor = cookieValue(rotated, "refresh_token");

    assertEquals(HttpStatus.OK, rotated.getStatusCode());
    assertThat(rotated.getBody()).isNull();
    assertThat(successor).isNotEqualTo(original);
    assertEquals(HttpStatus.UNAUTHORIZED, refresh(original).getStatusCode());
    ResponseEntity<JsonNode> revokedSuccessor = refresh(successor);
    assertEquals(HttpStatus.UNAUTHORIZED, revokedSuccessor.getStatusCode());
    assertThat(revokedSuccessor.getBody().path("code").asText()).isEqualTo("invalid_refresh_token");
  }

  @Test
  void simultaneousRefreshRequestsCannotCreateTwoActiveSuccessors() {
    String original = cookieValue(login(ACTIVE_EMAIL, PASSWORD), "refresh_token");
    String originalHash = sha256(original);
    String familyId =
        mongoTemplate
            .findOne(
                Query.query(Criteria.where("tokenHash").is(originalHash)),
                RefreshTokenDocument.class)
            .familyId();
    CountDownLatch start = new CountDownLatch(1);
    CompletableFuture<ResponseEntity<JsonNode>> first =
        CompletableFuture.supplyAsync(() -> awaitAndRefresh(start, original));
    CompletableFuture<ResponseEntity<JsonNode>> second =
        CompletableFuture.supplyAsync(() -> awaitAndRefresh(start, original));
    start.countDown();

    ResponseEntity<JsonNode> firstResponse = first.orTimeout(10, TimeUnit.SECONDS).join();
    ResponseEntity<JsonNode> secondResponse = second.orTimeout(10, TimeUnit.SECONDS).join();
    long successfulRotations =
        java.util.stream.Stream.of(firstResponse, secondResponse)
            .filter(response -> response.getStatusCode() == HttpStatus.OK)
            .count();
    long activeTokens =
        mongoTemplate
            .find(Query.query(Criteria.where("familyId").is(familyId)), RefreshTokenDocument.class)
            .stream()
            .filter(token -> "ACTIVE".equals(token.state()))
            .count();

    assertThat(successfulRotations).isEqualTo(1);
    assertThat(activeTokens).isLessThanOrEqualTo(1);
    assertThat(firstResponse.getStatusCode().value()).isIn(200, 401, 503);
    assertThat(secondResponse.getStatusCode().value()).isIn(200, 401, 503);
  }

  @Test
  void logoutIsIdempotentAndRevokesRefreshFamily() {
    String refreshToken = cookieValue(login(ACTIVE_EMAIL, PASSWORD), "refresh_token");

    ResponseEntity<Void> first = logout(refreshToken);
    ResponseEntity<Void> second = logout(refreshToken);

    assertEquals(HttpStatus.NO_CONTENT, first.getStatusCode());
    assertEquals(HttpStatus.NO_CONTENT, second.getStatusCode());
    assertThat(setCookie(first, "access_token"))
        .contains("Max-Age=0", "HttpOnly", "Secure", "Path=/api", "SameSite=Lax");
    assertThat(setCookie(first, "refresh_token"))
        .contains("Max-Age=0", "HttpOnly", "Secure", "Path=/api", "SameSite=Lax");
    assertEquals(HttpStatus.UNAUTHORIZED, refresh(refreshToken).getStatusCode());

    ResponseEntity<Void> unknown = logout("A".repeat(43));
    assertEquals(HttpStatus.NO_CONTENT, unknown.getStatusCode());
  }

  @Test
  void refreshRejectsMalformedTokenAndRechecksCurrentAccountStatus() {
    assertEquals(HttpStatus.UNAUTHORIZED, refresh("not-a-refresh-token").getStatusCode());
    String refreshToken = cookieValue(login(ACTIVE_EMAIL, PASSWORD), "refresh_token");
    jdbcTemplate.update("UPDATE user_account SET status = 'INACTIVE' WHERE id = ?", 101L);

    ResponseEntity<JsonNode> response = refresh(refreshToken);
    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    assertThat(response.getBody().path("code").asText()).isEqualTo("invalid_refresh_token");
  }

  @Test
  void expiredRefreshTokenCannotBeUsedEvenBeforeMongoTtlCleanup() {
    String refreshToken = cookieValue(login(ACTIVE_EMAIL, PASSWORD), "refresh_token");
    String tokenHash = sha256(refreshToken);
    mongoTemplate.updateFirst(
        Query.query(Criteria.where("tokenHash").is(tokenHash)),
        new Update().set("expiresAt", java.time.Instant.now().minusSeconds(10)),
        RefreshTokenDocument.class);

    ResponseEntity<JsonNode> response = refresh(refreshToken);
    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    assertThat(response.getBody().path("code").asText()).isEqualTo("invalid_refresh_token");
  }

  @Test
  void loginFailureLimitReturns429AndRetryAfter() {
    assertEquals(HttpStatus.UNAUTHORIZED, login(ACTIVE_EMAIL, "wrong-1").getStatusCode());
    assertEquals(HttpStatus.UNAUTHORIZED, login(ACTIVE_EMAIL, "wrong-2").getStatusCode());

    ResponseEntity<JsonNode> limited = login(ACTIVE_EMAIL, "wrong-3");
    assertEquals(HttpStatus.TOO_MANY_REQUESTS, limited.getStatusCode());
    assertThat(limited.getHeaders().getFirst("Retry-After")).isNotBlank();
    assertThat(limited.getBody().path("code").asText()).isEqualTo("rate_limited");
  }

  @Test
  void refreshFailureLimitReturns429() {
    String unknownToken = "A".repeat(43);
    for (int attempt = 0; attempt < rateLimitSettings.getRefreshIpLimit(); attempt++) {
      assertEquals(HttpStatus.UNAUTHORIZED, refresh(unknownToken).getStatusCode());
    }

    ResponseEntity<JsonNode> limited = refresh(unknownToken);
    assertEquals(HttpStatus.TOO_MANY_REQUESTS, limited.getStatusCode());
    assertThat(limited.getHeaders().getFirst("Retry-After")).isNotBlank();
    assertThat(limited.getBody().path("code").asText()).isEqualTo("rate_limited");
  }

  @Test
  void duplicateNormalizedEmailsFailClosed() {
    jdbcTemplate.update(
        "INSERT INTO user_account (id, role_id, email, status, password_hash) "
            + "VALUES (?, 1, ?, 'ACTIVE', ?)",
        303L,
        " ACTIVE@example.com ",
        passwordEncoder.encode(PASSWORD));

    ResponseEntity<JsonNode> response = login(ACTIVE_EMAIL, PASSWORD);
    assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
    assertThat(response.getBody().path("code").asText()).isEqualTo("service_unavailable");
  }

  private ResponseEntity<JsonNode> login(String email, String password) {
    return login(email, password, "mobile");
  }

  private ResponseEntity<JsonNode> login(String email, String password, String platform) {
    return restTemplate.postForEntity(
        baseUrl() + "/auth/login",
        Map.of("email", email, "password", password, "platform", platform),
        JsonNode.class);
  }

  private ResponseEntity<JsonNode> refresh(String token) {
    HttpHeaders headers = new HttpHeaders();
    headers.add(HttpHeaders.COOKIE, "refresh_token=" + token);
    return restTemplate.exchange(
        baseUrl() + "/auth/refresh", HttpMethod.POST, new HttpEntity<>(headers), JsonNode.class);
  }

  private ResponseEntity<Void> logout(String token) {
    HttpHeaders headers = new HttpHeaders();
    if (token != null) {
      headers.add(HttpHeaders.COOKIE, "refresh_token=" + token);
    }
    return restTemplate.exchange(
        baseUrl() + "/auth/logout", HttpMethod.POST, new HttpEntity<>(headers), Void.class);
  }

  private String cookieValue(ResponseEntity<?> response, String cookieName) {
    String setCookie = setCookie(response, cookieName);
    return setCookie.substring((cookieName + "=").length(), setCookie.indexOf(';'));
  }

  private String setCookie(ResponseEntity<?> response, String cookieName) {
    List<String> setCookies = response.getHeaders().getValuesAsList(HttpHeaders.SET_COOKIE);
    for (int index = 0; index < setCookies.size(); index++) {
      String value = setCookies.get(index);
      if (value.startsWith(cookieName + "=")) {
        StringBuilder cookie = new StringBuilder(value);
        for (int next = index + 1; next < setCookies.size(); next++) {
          String continuation = setCookies.get(next);
          if (continuation.startsWith("access_token=")
              || continuation.startsWith("refresh_token=")) {
            break;
          }
          cookie.append(", ").append(continuation);
        }
        return cookie.toString();
      }
    }
    throw new AssertionError("Missing Set-Cookie for " + cookieName);
  }

  private ResponseEntity<JsonNode> awaitAndRefresh(CountDownLatch start, String token) {
    try {
      start.await();
      return refresh(token);
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("Concurrent refresh test was interrupted.", exception);
    }
  }

  private String baseUrl() {
    return "http://localhost:" + port + "/api";
  }

  private String sha256(String value) {
    try {
      byte[] digest =
          java.security.MessageDigest.getInstance("SHA-256")
              .digest(value.getBytes(StandardCharsets.UTF_8));
      return java.util.HexFormat.of().formatHex(digest);
    } catch (java.security.NoSuchAlgorithmException exception) {
      throw new IllegalStateException(exception);
    }
  }

  private static KeyFiles createKeyFiles() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      KeyPair keyPair = generator.generateKeyPair();
      Path directory = Files.createTempDirectory("ds-auth-test-keys");
      Path privateKey = directory.resolve("private.pem");
      Path publicKey = directory.resolve("public.pem");
      writePem(privateKey, "PRIVATE KEY", ((RSAPrivateKey) keyPair.getPrivate()).getEncoded());
      writePem(publicKey, "PUBLIC KEY", ((RSAPublicKey) keyPair.getPublic()).getEncoded());
      return new KeyFiles(privateKey, publicKey);
    } catch (Exception exception) {
      throw new ExceptionInInitializerError(exception);
    }
  }

  private static void writePem(Path path, String label, byte[] encoded) throws Exception {
    String contents =
        "-----BEGIN "
            + label
            + "-----\n"
            + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(encoded)
            + "\n-----END "
            + label
            + "-----\n";
    Files.writeString(path, contents, StandardCharsets.US_ASCII);
  }

  private record KeyFiles(Path privateKey, Path publicKey) {}
}
