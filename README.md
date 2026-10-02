# QuiStock Auth API

Serviço separado para login por email e senha, emissão de JWT RS256, rotação de refresh token e logout. Contas e hashes BCrypt são provisionados por outro fluxo no PostgreSQL. O serviço não cadastra usuários nem mantém perfil.

## Requisitos

- Java 25 para executar o Gradle localmente.
- PostgreSQL com o schema QuiStock instalado e uma credencial que tenha somente `SELECT` nas colunas `id`, `email`, `status` e `password_hash` de `user_account`.
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
4. Inicie a API com `./gradlew bootRun` (Windows: `./gradlew.bat bootRun`). Com o `.env.example`, a API usa a porta `8090` e o context path `/api`.

O MongoDB deve anunciar o mesmo host alcançável pela aplicação em sua URI de replica set. Em execução local, um replica set de um nó pode usar `mongodb://localhost:27017/?replicaSet=rs0`; inicialize-o com `rs.initiate()` antes de iniciar a API. Em containers, configure o endereço anunciado para que o serviço também consiga alcançá-lo.

## Rotas

- `POST /api/auth/login` — valida a conta `ACTIVE` no SQL e devolve access e refresh tokens.
- `POST /api/auth/refresh` — consome o refresh atual e cria seu sucessor atomicamente.
- `POST /api/auth/logout` — revoga a família do refresh token; retorna `204`, inclusive quando o token já não existe.
- `GET /api/.well-known/jwks.json` — publica apenas as chaves públicas RS256.

As respostas de login e refresh não são armazenáveis em cache. O access token dura 5 minutos; refresh tokens duram 15 dias após cada emissão. O refresh original é opaco; somente seu SHA-256 é gravado no MongoDB.

## Validação

Os testes de integração usam PostgreSQL e MongoDB com replica set via Testcontainers. Docker precisa estar instalado e com o daemon em execução:

```sh
./gradlew spotlessCheck checkstyleMain pmdMain test jacocoTestCoverageVerification
```

O CI também constrói a imagem ARM64 e valida a cobertura mínima de 80%.

## Mobile

O repositório Mobile não faz parte desta implementação. Uma tarefa futura substituirá Firebase Auth por estas rotas; Firebase Analytics e Crashlytics podem continuar no app.
