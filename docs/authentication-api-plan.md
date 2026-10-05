> Routing update (2026-10-05): APIs now default to root context. Public prefixes and client bases are deployment configuration. Historical Mobile examples below describe the earlier deployment; see README for the current environment contract.
# Authentication API Implementation Plan

- **Target repository:** [QuiStock/DS_Auth](https://github.com/QuiStock/DS_Auth)
- **Document location:** `docs/authentication-api-plan.md` in QuiStock/DS_Auth
- **Repository review date:** 2026-10-02
- **Status:** the platform and cookie contract described in this revision is implemented in the PR branch; CI validation is pending. Deployment secrets and URLs, the SQL migration, and future Mobile integration remain pending. This implementation does not modify the Mobile repository.

This document defines the contract between DS_Auth, DS_Backend, the PostgreSQL schema, and the QuiStock Android app. The local API implementation is described in section 9.1; Mobile integration and production configuration are later deliverables.

## 1. Scope

DS_Auth is responsible only for authenticating credentials and managing sessions: login, refresh-token rotation, and logout. It will not provide account registration, profiles, user editing, or password recovery.

- PostgreSQL remains the source of truth for user ID, email, status, and password hash.
- MongoDB stores only refresh-token records and session state. It stores no password, password hash, or profile copy.
- The access token is an RS256 JWT whose subject is the decimal `user_account.id` and whose claims include `email`.
- Access tokens last 5 minutes. Each refresh token lasts 15 days from issuance; rotation renews this period as a sliding inactivity timeout.
- The business API uses the `quistock-api` audience.
- No authentication route will be added to DS_Backend; DS_Auth is a separate service.

### Out of scope for this delivery

Account creation and maintenance belong to a separate flow that writes to SQL. That flow also generates a BCrypt-compatible `password_hash`. DS_Auth does not create or update accounts and uses a read-only SQL credential.

The Mobile app has a visual registration screen, but its current fragment only inflates the layout and does not submit data. The inspected DS_Backend code also has no user route. DS_Auth will not make Mobile registration work; a future integration must define or implement that separate flow.

## 2. Evidence from the three repositories

| Project | Observed state | Implementation consequence |
| --- | --- | --- |
| DS_Backend | Spring Boot uses the root context by default; every route requires a JWT. The decoder accepts RS256 and validates issuer, audience, a positive numeric subject, and email. The default audience is `quistock-api`. | DS_Auth publishes a JWKS and issues tokens with this exact contract. Preserve the complete configured JWKS URL, without inferring a public prefix. |
| PostgreSQL | `user_account` has `id BIGINT`, `role_id`, `email VARCHAR(255) UNIQUE NOT NULL`, `password_hash VARCHAR(255) NOT NULL`, and a `user_status` enum with `ACTIVE`/`INACTIVE`; `role` has `code` and `name`. The current uniqueness constraint is case-sensitive. | DS_Auth reads the account fields and role name to enforce platform access. Case-insensitive login requires a duplicate preflight and a functional unique index in the database. |
| DS_Auth | Spring Boot 4.1/Java 25 scaffold. It includes JPA, PostgreSQL, and H2, but not MongoDB, Spring Security/JWT, controllers, or authentication logic. `ddl-auto=update` and `show-sql=true` are enabled. | Remove JPA/automatic DDL and SQL logging; use read-only SQL access and add MongoDB and JWT support. |
| Mobile | On branch `main`, login uses Firebase Auth with email/password. Firebase Analytics and Crashlytics are also used. `UserPreferences` stores only the Firebase ID in ordinary SharedPreferences; there is no auth client, cookie manager, Bearer interceptor, or renewal. | Future login moves to DS_Auth. Keep Analytics/Crashlytics. This analysis does not change the Mobile code. |
| Mobile ↔ DS_Backend | Retrofit uses `BACKEND_BASE_URL` ending in `/api/`; `POST /chat` matches `/api/chat`. Mobile sends `user_id` and `message`, but the backend DTO accepts only `message`. The backend requires JWT, and the current Retrofit client does not send `Authorization`. | Future integration aligns the payload to `message` and sends Bearer authentication from the native cookie manager. The website cannot read an `HttpOnly` cookie; website requests need a same-site gateway/backend cookie integration. Do not trust identity in the request body; the server uses the validated subject when it needs the user ID. |
| Mobile registration | `CadastroPessoalFragment` only inflates the XML. There is no account-creation implementation. | The current screen is not a functional registration flow and is not served by DS_Auth. |

This inspection reflects the local branches available on 2026-10-01. Recheck branches before implementation.

## 3. Confirmed decisions

- Login uses email and password.
- DS_Auth is a separate service for authentication and sessions only.
- Account data remains in PostgreSQL; sessions and refresh tokens are stored in MongoDB.
- MongoDB runs as a replica set; transactions are required for atomic rotation and revocation.
- Password hashes use BCrypt. The default cost is 12 and can be changed per environment; the external SQL provisioner writes a compatible BCrypt hash.
- Accounts and hashes are provisioned by another SQL flow. DS_Auth has no registration endpoint and does not write to SQL.
- Mobile will remove Firebase Auth in a future integration; Firebase Analytics and Crashlytics may remain.
- The current request analyzes Mobile and updates this plan; it does not change any file in the Mobile repository.
- The subject is the positive decimal SQL ID represented as a string; `email` is a required claim.
- Login requires `platform` with exactly `mobile` or `website`. Gerente Regional is denied on `mobile`; Repositor is denied on `website`, with `403 Forbidden`.
- Access tokens last 5 minutes; refresh tokens last 15 days, renewed on each rotation.
- RS256 signing is compatible with the current DS_Backend decoder.
- The audience is `quistock-api`.
- Do not include a role claim in the JWT. Read the role from SQL when checking the requested login platform.
- Login and refresh set HTTP-only access and refresh cookies and return no body or user profile. The cookie `Max-Age` is expressed in seconds by the HTTP cookie standard: 300 seconds for access and 1,296,000 seconds for refresh.
- Refresh and logout read the refresh token from its cookie. Logout expires both cookies with `Max-Age=0`; the cookie name, path, domain, and security attributes must match the issued cookies.
- Each login creates an independent family. V1 has no per-user session limit or route to revoke every family; logout revokes the family of the supplied refresh token.
- The JWT subject is the SQL account ID and the required `email` claim is the canonical SQL email. Neither value is returned in the login or refresh response body.

## 4. HTTP contract

DS_Auth uses the root context by default; the deployment defines public prefixes. The complete external paths are:

- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /.well-known/jwks.json` — public, no authentication required

These four routes are public in the security filter; refresh and logout authenticate through the `refresh_token` cookie. The API is stateless and uses no server-side HTTP session. Login and refresh responses set the `access_token` and `refresh_token` cookies with `HttpOnly`, `Path=/`, configured `SameSite`/`Secure`/optional `Domain`, and the matching token lifetime. Return an empty body and `Cache-Control: no-store`; do not put tokens or user information in JSON. `Max-Age` uses seconds, as defined by HTTP cookies, not milliseconds. `Lax` is the default `SameSite`; `None` requires `Secure` and a CSRF/origin policy at the website gateway. Logout returns `204 No Content` and both cookies with empty values and `Max-Age=0`, preserving their original cookie scope and attributes. Paths not listed here are outside the contract.

Use port 8090 in the local profile to avoid colliding with DS_Backend, which uses 8080. Mobile will receive an `AUTH_BASE_URL` ending in `/api/`. It may point to the same gateway as the backend if the gateway routes `/auth/**` and `/.well-known/**` to DS_Auth; if the services use separate hosts, configure the auth origin.

### Login

Request:

    {
      "email": "person@example.com",
      "password": "password provided by the user",
      "platform": "mobile"
    }

`platform` is required and accepts only `mobile` or `website`. Gerente Regional may use `website` and receives `403` for `mobile`. Repositor may use `mobile` and receives `403` for `website`. Other active roles are allowed on both platforms unless a later rule says otherwise.

Success: `200 OK`, empty body, and two `Set-Cookie` headers. `access_token` contains the RS256 JWT with `Max-Age=300`; `refresh_token` contains the opaque token with `Max-Age=1296000`. Both are `HttpOnly`. No user object or tokens are included in a response payload.

Trim surrounding whitespace and lowercase the email using `Locale.ROOT`. Do not alter the password. Look up the same normalized form. The `email` claim contains the canonical email stored in SQL.

Unknown email, incorrect password, and `INACTIVE` account return the same `401` and the same generic code/message. The response must not reveal whether the account exists. For an unknown email, compare the password against a fake BCrypt hash created in memory with the same cost to reduce observable timing differences. A valid account with a role that is not permitted on the requested platform receives `403` with code `platform_not_allowed` and no cookies.

### Refresh

Request: send the `refresh_token` cookie from the login response; there is no JSON request body.

Success: `200 OK`, empty body, and new `access_token`/`refresh_token` cookies. Consume the submitted token in the same transaction that creates its successor. Cookie max ages are reset to 300 and 1,296,000 seconds from issuance.

Unknown, expired, consumed, or revoked tokens return `401`. If a consumed token is presented again before its original expiry, revoke the entire session family. Expired old tokens may have been removed by the TTL index; in that case return `401` without revoking other sessions.

### Logout

Request: send the `refresh_token` cookie; there is no JSON request body.

Revoke the family of the supplied refresh token and return `204 No Content`. Unknown or already revoked tokens also return `204`, making the operation idempotent. Return both issued cookie names with empty values and `Max-Age=0`, preserving the original path, domain, `SameSite`, `Secure`, and `HttpOnly` attributes. The current access token remains usable in DS_Backend until it expires.

### Uniform error format

Use JSON `{ "code": "...", "message": "..." }` for responses with a body:

| Case | HTTP | `code` |
| --- | --- | --- |
| Missing or invalid field | 400 | `invalid_request` |
| Unknown/incorrect credentials or inactive account | 401 | `invalid_credentials` |
| Account role cannot use requested platform | 403 | `platform_not_allowed` |
| Invalid, expired, revoked, or replayed refresh token | 401 | `invalid_refresh_token` |
| Rate limit exceeded | 429 | `rate_limited`, with `Retry-After` |
| SQL or MongoDB unavailable | 503 | `service_unavailable` |
| Unexpected error | 500 | `internal_error`, with no internal details |

Never return passwords, hashes, stack traces, email existence, or account status in a public message.

## 5. SQL access and account provisioning

Use JDBC (`JdbcClient`/`JdbcTemplate`), without mutable entities or JPA. Planned query:

    SELECT u.id, u.email, u.status::text AS status, u.password_hash, r.code, r.name
    FROM user_account u
    JOIN role r ON r.id = u.role_id
    WHERE lower(btrim(u.email)) = ?

The DS_Auth SQL account receives only `SELECT` on `user_account.id`, `email`, `status`, `password_hash`, and `role_id`, plus `role.id`, `code`, and `name`. It receives no `INSERT`, `UPDATE`, `DELETE`, DDL, or profile/store permissions. The service compares the password in memory using BCrypt and never logs credentials.

Before applying the email-normalization migration:

    SELECT lower(btrim(email)), count(*)
    FROM user_account
    GROUP BY lower(btrim(email))
    HAVING count(*) > 1;

Resolve duplicates and create the index below through a database migration, never through Hibernate/DS_Auth. The existing unique constraint on the original text may remain.

    CREATE UNIQUE INDEX uq_user_account_email_normalized
      ON user_account (lower(btrim(email)));

The table also requires `role_id`; the external provisioner must assign a valid role and satisfy the other schema foreign keys even though DS_Auth does not issue a role in the token. DS_Auth can be developed and tested with fixture accounts; real-user login depends on the external provisioning flow.

## 6. MongoDB sessions

The `refresh_token` collection stores one document per issued token:

| Field | Type/use |
| --- | --- |
| `id` | Internal UUID |
| `family_id` | UUID shared by the rotation chain; indexed |
| `user_account_id` | `BIGINT`/`Long` with the SQL ID, no profile |
| `token_hash` | SHA-256 of the opaque token; unique index |
| `state` | `ACTIVE`, `CONSUMED`, or `REVOKED` |
| `created_at`, `expires_at` | UTC; expires 15 days after issuance |
| `consumed_at`, `revoked_at` | Optional timestamps |
| `replaced_by_id` | Optional UUID of the successor token |

Generate refresh tokens with 32 cryptographically random bytes and Base64URL encoding without padding. Return the original token only in an `HttpOnly` cookie; persist and look up only its SHA-256 hash. Indexes: unique `token_hash`, `family_id`, and TTL on `expires_at`. TTL cleanup is eventual: every read checks state and expiry time. Create indexes through a versioned bootstrap/explicit database migration; do not rely on automatic ORM index creation.

Rotation runs in a MongoDB transaction: conditionally consume the still-valid active token, insert its successor, and set `replaced_by_id`. A replay detected before expiry revokes the family within the transaction and returns `401` after revocation is confirmed. A replica set is required at runtime and in integration tests; transactions do not work on a standalone MongoDB server. Mobile serializes concurrent refreshes to avoid accidental replay.

On refresh, query the SQL account's current status and password hash again. An inactive account cannot rotate. Use current SQL state; do not persist a role or profile in MongoDB.

## 7. JWT, keys, and DS_Backend compatibility

Required claims:

    {
      "iss": "<AUTH_JWT_ISSUER>",
      "aud": ["quistock-api"],
      "sub": "<positive decimal user_account.id>",
      "email": "person@example.com",
      "iat": 0,
      "exp": 0,
      "jti": "<unique UUID>"
    }

JOSE header: `alg=RS256` and `kid` identifying the active key. The difference between `exp` and `iat` is 300 seconds. JWKS contains public keys only. The private key stays in a secret manager or a protected mounted file, never in Git, SQL, MongoDB, or Mobile.

During key rotation, publish the old and new keys simultaneously and sign new tokens with the new `kid`. Keep the old public key in JWKS for at least 10 minutes after signing with it stops (5-minute token lifetime plus clock-skew/cache margin), then remove it.

The backend and auth service use exactly the same issuer and audience. DS_Backend points `AUTH_JWT_JWK_SET_URI` to the external path `/.well-known/jwks.json`. The JWKS endpoint requires no access token because the decoder must be able to fetch it without authentication.

## 8. Future Mobile and backend integration

This section aligns future implementation; it does not authorize or make changes to the Mobile repository in this task.

### Mobile

1. Add a Retrofit `AuthApi` for `auth/login`, `auth/refresh`, and `auth/logout`, with explicit snake_case DTOs using `@SerialName`; the current converter ignores unknown fields but does not automatically convert property names.
2. Replace the `AuthenticationPort` binding from `FirebaseAuthenticationPort` with a Retrofit implementation. Map `user.id`/`email` to the local `User` model and map `invalid_credentials` to the existing generic login error.
3. Use the native HTTP cookie manager to retain the `HttpOnly` cookies with their server-provided expiry. Never put token values in UI models, logs, Analytics, or Crashlytics.
4. On startup, call refresh and let the cookie manager attach the `refresh_token`; if the API returns `401`, clear the cookie manager and show login. `429`/`503`/network errors are transient and must not delete a potentially valid refresh token.
5. Use a separate HTTP client for auth and business calls. For DS_Backend's existing Bearer contract, the native client may read the access cookie from its private cookie jar and set `Authorization: Bearer <access_token>`; browser JavaScript must never read an `HttpOnly` cookie. The website must use a same-site gateway/backend integration that accepts the access cookie or translates it to the current Bearer contract. Refresh is serialized, and the business client retries a `401` once after renewal.
6. Logout attempts the API call and clears the cookie manager, including when offline; the server also expires both cookies on a successful response.
7. Stop treating the Firebase UID as identity. The SQL ID in the token is the identity accepted by the backend. `/api/chat` accepts only `message`; remove `user_id` from the Mobile DTO. If a future route needs the user, get the identity from the authenticated server-side subject.
8. Keep Firebase Analytics and Crashlytics if still needed; remove Firebase Auth only.
9. Configure `AUTH_BASE_URL` during build/deploy. Mobile sets `usesCleartextTraffic=false`, while `.env.example` suggests an HTTP emulator URL; local tests must use development HTTPS or allow HTTP only in debug builds, never release builds.

### DS_Backend

1. Change the local default JWKS URI to `http://localhost:8090/.well-known/jwks.json` and configure the corresponding public URL in deployment.
2. Configure the same `AUTH_JWT_ISSUER` as DS_Auth and keep audience `quistock-api`.
3. Keep business routes authenticated. Validate RS256, issuer, audience, positive subject, and email.
4. The backend Chat request accepts only `message`; align the Mobile DTO. For audit/user flows, use the authenticated JWT principal, never identity declared by the client.

## 9. DS_Auth scaffold configuration and changes

Remove `spring-boot-starter-data-jpa`, `spring.jpa.*` settings, automatic DDL, and SQL logging. Add Spring JDBC/PostgreSQL, Spring Data MongoDB, validation, Spring Security, and JOSE/JWT support. H2 does not replace PostgreSQL contract tests; use PostgreSQL integration tests and a Mongo replica set for transactions. Keep the existing Gradle quality gates.

Configure environment variables:

- DS_Auth: `SERVER_PORT` (8090 locally), `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` (read-only credential), `MONGODB_URI`, `MONGODB_DATABASE`, `AUTH_JWT_ISSUER`, `AUTH_JWT_AUDIENCE` (`quistock-api`), `AUTH_JWT_PRIVATE_KEY_PATH`, `AUTH_JWT_PUBLIC_KEY_PATH`, `AUTH_JWT_PREVIOUS_PUBLIC_KEYS`, `AUTH_JWT_KEY_ID`, `AUTH_COOKIE_SECURE`, `AUTH_COOKIE_SAME_SITE`, `AUTH_COOKIE_PATH`, `AUTH_COOKIE_DOMAIN`, `AUTH_BCRYPT_STRENGTH`, `AUTH_RATE_LIMIT_HMAC_KEY`, and `AUTH_TRUSTED_PROXY_CIDRS`.
- DS_Backend: `AUTH_JWT_ISSUER`, `AUTH_JWT_JWK_SET_URI`, `AUTH_JWT_AUDIENCE`.
- Mobile: `AUTH_BASE_URL` and `BACKEND_BASE_URL`, both ending in `/api/`.

Production requires HTTPS, secrets outside the repository, an available Mongo replica set, and restricted SQL credentials. The service fails at startup if a key, database, or issuer is missing/unsafe; it does not start with a default development key.

### Rate limiting

Apply a distributed limit across replicas using an atomic counter with MongoDB TTL or an equivalent gateway. Configurable defaults: 10 login attempts per IP in 15 minutes; 5 failures per IP plus normalized email in 15 minutes; 30 refresh calls per IP per minute. Above the limit, return `429` with `Retry-After`. Trust forwarded IP headers only from configured trusted proxies; do not accept arbitrary `X-Forwarded-For`. Counter IDs contain no plaintext IP/email: they use HMAC-SHA256 with a required secret of at least 32 bytes (`AUTH_RATE_LIMIT_HMAC_KEY`).

### 9.1 Local implementation in DS_Auth

The `QuiStock/DS_Auth` repository, local branch `feat/auth-api`, now implements this section's contract:

- JDBC reads `user_account` and the connection pool is read-only. Collisions in `lower(btrim(email))` fail closed until the functional index is installed.
- Login uses configurable BCrypt (default cost 12), a fake comparison for unknown email, and rejects passwords longer than BCrypt's 72-byte UTF-8 limit.
- RS256 JWTs use positive decimal `sub`, `email`, `iss`, `aud`, `iat`, `exp`, `jti`, and `kid`. Private and public keys are required; previous public keys can be published during rotation. The issuer must use HTTPS except on loopback.
- MongoDB stores only SHA-256 hashes of refresh tokens, applies idempotent indexes at startup, and refuses startup if `hello` does not report a replica set.
- Mongo rotation uses a transaction, conditional consumption, and family revocation on replay, including concurrent requests. Distributed counters use fixed windows and TTL expiry.
- All four contract routes are implemented, with uniform JSON errors, `Retry-After` for `429`, `Cache-Control: no-store` for authentication responses, and public JWKS.
- The DS_Auth `README.md` covers local configuration, database requirements, key generation, and validation commands. `.env.example` documents configuration without real secrets.
- Testcontainers tests cover PostgreSQL and a Mongo replica set, JWT/JWKS issuance and verification, credentials, validation, refresh/replay, expiration, logout, rate limits, and collisions in normalized emails.

The DS_Backend JWKS configuration, functional SQL index migration, deployment secrets/URLs, and Mobile integration remain external dependencies for the DS_Auth implementation. End-to-end emulator tests belong to the Mobile integration delivery.

### 9.2 Local validation results

- On 2026-10-02, validation ran on Windows with Gradle 9.7.1, Temurin JDK 25, and Docker Desktop. Testcontainers started PostgreSQL 16 and MongoDB 8.0 as a replica set.
- Passing command: `./gradlew spotlessCheck checkstyleMain pmdMain test jacocoTestCoverageVerification --no-daemon --console=plain` (Windows: `gradlew.bat`). All 17 tests passed, including HTTP integration, PostgreSQL, and transactional MongoDB rotation. JaCoCo line coverage was 85.17%, above the 80% minimum.
- Spotless, Checkstyle, and PMD passed. Main and test sources also compiled successfully.
- On this Windows environment, `TEMP`/`TMP` had to point to a local directory and `-Djdk.net.unixdomain.tmpdir` had to point to that directory because Gradle could not establish its loopback connection using the default temporary directory. This is a local environment workaround and does not change service code.
- Tests start the server with the root context, matching the documented contract. End-to-end Mobile emulator validation, the SQL migration, and deployment secrets/URLs remain pending.

## 10. Acceptance criteria and tests

### DS_Auth and databases

- Login with an `ACTIVE` account and correct password issues tokens; `user.id`/email match the subject/email claim; configured audience/issuer are present; `exp - iat = 300`.
- Unknown email, wrong password, and `INACTIVE` account return the same `401`, body, and comparable processing path.
- Missing/invalid fields return `400`; too many attempts return `429` with `Retry-After`.
- Plaintext passwords never reach the database, logs, MongoDB, or response. MongoDB stores a refresh-token hash, never the original token.
- The read-only SQL credential cannot insert, update, or delete.
- Valid refresh consumes a token and issues a successor in a transaction; replay of a still-valid old token revokes the family; concurrent refresh does not issue two active successors.
- Unknown/expired/revoked refresh returns `401`; logout revokes an active family and is idempotent.
- SQL/MongoDB outages return `503` without stack traces or credentials in logs.
- Expiration is enforced by the application, not by eventual MongoDB TTL cleanup.
- Public JWKS contains only public keys and verifies a valid RS256 token. The backend rejects unknown `kid`, wrong issuer/audience, invalid signature, invalid subject, missing email, and expired token.
- After an account is inactivated in SQL, login and refresh fail. An already-issued access token remains valid until it expires.
- Login rejects Gerente Regional on `mobile` and Repositor on `website` with `403`; missing or unsupported `platform` returns `400`.
- Login and refresh return no JSON body, set the two HTTP-only cookies with TTL-based `Max-Age` in seconds, and expose no user identity. Logout revokes the refresh family and expires both cookies with `Max-Age=0`.

### Mobile ↔ DS_Auth ↔ DS_Backend

- Valid login shows an authenticated state without exposing tokens to the ViewModel/UI.
- Refresh token survives process restart in protected storage; access token stays in memory and can be renewed.
- A backend `401` triggers one renewal and at most one request retry; failed refresh clears the session and returns to login.
- Concurrent client refreshes are serialized; logout clears the session even while offline.
- Protected Mobile → `POST /api/chat` carries a valid Bearer token and sends the agreed DTO (`message`).
- DS_Backend validates tokens published by DS_Auth; a route without a token or with an invalid token returns `401`.
- The external SQL provisioning flow creates a valid account and BCrypt hash before a real user can log in.
- The current registration screen is not an acceptance criterion for DS_Auth and remains without persistence until a separate delivery.

## 11. Implementation order

1. Treat this plan as the contract for the three projects. **Complete.**
2. Preflight normalized email duplicates in SQL, resolve collisions, and apply the functional unique index. **Pending in the PostgreSQL environment.**
3. Adjust DS_Auth scaffold dependencies/configuration; remove JPA/DDL/SQL logging and configure read-only SQL plus Mongo replica set. **Implemented locally.**
4. Implement SQL lookup/authentication, login contract, and RS256/JWKS issuance. **Implemented locally.**
5. Implement documents, indexes, refresh transactions, replay handling, logout, rate limiting, and errors. **Implemented locally.**
6. Update DS_Backend JWKS configuration.
7. In a future task, update Mobile for login/logout/refresh, protected storage, and Retrofit Bearer authentication; align chat requests and network states.
8. Run unit tests, PostgreSQL/Mongo replica set integration tests, and Gradle gates after the platform and cookie contract changes. The initial implementation passed all 17 tests on 2026-10-02; this revision still needs validation. Validate end-to-end on the emulator in the Mobile delivery.
9. Configure secrets, issuer, public JWKS, HTTPS URLs, read-only credentials, and monitoring per environment before releasing the API.

## 12. Production dependencies

- The owner of the external SQL flow provisions users and generates compatible BCrypt hashes.
- Apply the case-insensitive unique index after resolving duplicate values.
- Public URLs, issuer, JWKS, keys, and credentials are provided per deployment environment; they are not fixed in this document.
- Runtime and integration MongoDB instances use a replica set.
- Mobile is compatible only after the integration task described in section 8; this delivery does not change its repository.
