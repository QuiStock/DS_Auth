# QuiStock Auth API

Serviço separado para login por email e senha, emissão de JWT RS256, rotação de refresh token e logout. Contas e hashes BCrypt são provisionados por outro fluxo no PostgreSQL. O serviço não cadastra usuários nem mantém perfil.

## Plano de implementação e integração

O contrato entre DS_Auth, DS_Backend, o schema PostgreSQL e a integração futura com o Mobile está em [docs/authentication-api-plan.md](docs/authentication-api-plan.md) (em inglês).

## Requisitos

- Java 25 para executar o Gradle localmente.
- PostgreSQL com o schema QuiStock instalado e uma credencial que tenha somente `SELECT` nas colunas `id`, `email`, `status`, `password_hash` e `role_id` de `user_account`, além de `id`, `code` e `name` de `role`.
- MongoDB configurado como replica set. A aplicação valida essa condição no startup porque a rotação de refresh token usa transações.
- Chave RSA privada PKCS#8 e chave pública X.509, ambas com pelo menos 2048 bits.

Antes de habilitar login de usuários reais, verifique colisões de email normalizado e aplique o índice funcional depois de resolver os duplicados:

```sql
SELECT lower(btrim(email)), count(*)
FROM user_account
GROUP BY lower(btrim(email))
HAVING count(*) > 1;

CREATE UNIQUE INDEX uq_user_account_email_normalized
  ON user_account (lower(btrim(email)));
```

## Configuração local

1. Copie `.env.example` para `.env` e informe URL, usuário read-only e senha do PostgreSQL, URI do replica set MongoDB e um segredo aleatório com pelo menos 32 bytes em `AUTH_RATE_LIMIT_HMAC_KEY`.
2. Gere as chaves de desenvolvimento. Com OpenSSL:

   ```sh
   mkdir -p dev-keys
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out dev-keys/private-key.pem
   openssl pkey -in dev-keys/private-key.pem -pubout -out dev-keys/public-key.pem
   ```

   No PowerShell, crie a pasta com `New-Item -ItemType Directory -Force dev-keys`. Os arquivos dessa pasta são ignorados pelo Git. Nunca use chaves locais em produção.
3. Confirme `AUTH_JWT_ISSUER`, `AUTH_JWT_KEY_ID` e os caminhos de chave no `.env`. HTTP só é aceito para issuer em loopback; os demais ambientes exigem HTTPS.
4. Inicie a API com `./gradlew bootRun` (Windows: `./gradlew.bat bootRun`). Com o `.env.example`, a API usa a porta `8090` e o contexto raiz.

O MongoDB deve anunciar o mesmo host alcançável pela aplicação em sua URI de replica set. Em execução local, um replica set de um nó pode usar `mongodb://localhost:27017/?replicaSet=rs0`; inicialize-o com `rs.initiate()` antes de iniciar a API. Em containers, configure o endereço anunciado para que o serviço também consiga alcançá-lo.

## Rotas

- `POST /auth/login` — recebe email, senha e `platform` (`mobile` ou `website`); valida a conta `ACTIVE` e a plataforma permitida para o perfil. Gerente Regional não pode entrar pelo app; Repositor não pode entrar pelo website. Em sucesso, define os cookies `access_token` e `refresh_token`.
- `POST /auth/refresh` — lê o refresh token do cookie, consome o valor atual e define os cookies com a nova sessão atomicamente.
- `POST /auth/logout` — revoga a família do refresh token do cookie; retorna `204` e expira os cookies mesmo quando o token já não existe.
- `GET /.well-known/jwks.json` — publica apenas as chaves públicas RS256.

As rotas de autenticação não enviam informações de usuário nem tokens no payload. Os tokens são enviados em cookies `HttpOnly`; o `Max-Age` segue o TTL de cada token e é expresso em segundos pelo padrão de cookies HTTP (300 para access e 1.296.000 para refresh). Respostas de login e refresh usam `Cache-Control: no-store`. O refresh original é opaco; somente seu SHA-256 é gravado no MongoDB.

Configure `AUTH_COOKIE_SECURE=true` fora do ambiente local HTTPS. `SameSite` é configurável; `SameSite=None` exige cookies `Secure`. Configure o domínio e o `SameSite` de acordo com os domínios do website e da API.

## Validação

Os testes de integração usam PostgreSQL e MongoDB com replica set via Testcontainers. Docker precisa estar instalado e com o daemon em execução:

```sh
./gradlew spotlessCheck checkstyleMain pmdMain test jacocoTestCoverageVerification
```

O CI também constrói a imagem ARM64 e valida a cobertura mínima de 80%.

## Mobile

O repositório Mobile não faz parte desta implementação. Uma tarefa futura substituirá Firebase Auth por estas rotas; Firebase Analytics e Crashlytics podem continuar no app.

## Java 25 e roteamento por ambiente

Use Eclipse Temurin JDK 25 e o wrapper versionado: `./gradlew clean check bootJar`
(Windows: `./gradlew.bat clean check bootJar`). Configure `JAVA_HOME` e selecione o mesmo
JDK na IDE para o projeto e para Gradle. Não é necessário instalar Gradle globalmente.
Os testes de integração exigem Docker; não devem ser omitidos na validação da PR.
CI verifica Java 25 no toolchain, workflow e imagens e executa a JVM ARM64 via QEMU.

As rotas usam contexto raiz por padrão. `SERVER_PORT` controla a porta interna;
`SERVER_SERVLET_CONTEXT_PATH` permite um contexto temporário durante a migração.
O gateway define e remove prefixos públicos, por exemplo `/api/auth-service` e
`/api/core-service`. Configure `AUTH_COOKIE_PATH` com o prefixo público da Auth
(`/` no acesso direto), independentemente do contexto interno. Os cookies continuam
configuráveis por `AUTH_COOKIE_DOMAIN`, `AUTH_COOKIE_SECURE` e `AUTH_COOKIE_SAME_SITE`.

Configure o mesmo `AUTH_JWT_ISSUER` e `AUTH_JWT_AUDIENCE` nas duas APIs. Backend recebe
`AUTH_JWT_JWK_SET_URI` completo, por exemplo `http://localhost:8090/.well-known/jwks.json`
para a Auth local na porta 8090; nenhum prefixo é concatenado pela aplicação.
Preserve o issuer ao migrar o roteamento. Em produção forneça explicitamente as URLs,
credenciais de banco e configurações JWT. ERP exige `ERP_API_BASE_URL` HTTP(S) quando
`ERP_SYNC_ENABLED=true`; `ERP_API_PRODUCTS_PATH` é um path absoluto (padrão `/products`).
O exemplo local espera um ERP em `http://localhost:8091`; os testes usam fixture HTTP local.

Smoke funcional: `python scripts/smoke-routing.py`. Configure `SMOKE_AUTH_BASE_URL`,
`SMOKE_BACKEND_BASE_URL`, `SMOKE_EMAIL`, `SMOKE_PASSWORD` e `SMOKE_PLATFORM` (padrão `mobile`).
As bases incluem somente os prefixos públicos efetivamente usados. Execute com acesso
direto e depois com um gateway que remova os prefixos, usando o mesmo artefato.
O smoke cobre JWKS, login, consulta autenticada, refresh e logout sem imprimir tokens.
Health/probes e rollout serão tratados na entrega de health e no Infra.
Promova imagem e configuração de roteamento juntas; o rollback deve restaurar ambas.
