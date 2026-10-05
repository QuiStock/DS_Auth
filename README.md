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

## Chaves RSA no Vercel

No Vercel, configure o conteúdo PEM em Base64 nas variáveis de ambiente `AUTH_JWT_PRIVATE_KEY_BASE64` e `AUTH_JWT_PUBLIC_KEY_BASE64`. O carregador dá prioridade a essas variáveis quando preenchidas; os caminhos `AUTH_JWT_PRIVATE_KEY_PATH` e `AUTH_JWT_PUBLIC_KEY_PATH` continuam disponíveis para execução local.

No PowerShell, informe o caminho de uma pasta segura fora do repositório que contenha o par de produção e gere o valor de cada arquivo:

```powershell
$keyDirectory = Read-Host "Caminho da pasta segura com os PEMs de produção"
[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $keyDirectory "private-key.pem")))
[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $keyDirectory "public-key.pem")))
```

Copie cada saída para a variável correspondente em **Vercel → Project → Settings → Environment Variables**, marque os valores como sensíveis e faça um novo deploy. Gere um par RSA exclusivo para produção; não use nem comite os arquivos de desenvolvimento. Base64 representa o conteúdo, mas não o protege sozinho: trate o valor da chave privada como segredo.

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
O CI usa Java 25 e executa a JVM ARM64 via QEMU.

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

Promova imagem e configuração de roteamento juntas; o rollback deve restaurar ambas.

## Health público

`GET /health` dispensa autenticação e retorna apenas `{"status":"UP"}` (HTTP 200)
ou `{"status":"DOWN"}` (HTTP 503). O contexto configurado se aplica à rota; o gateway
pode acrescentar/remover o prefixo público. Nenhum outro endpoint Actuator é exposto.
É readiness, não liveness: uma dependência indisponível deve retirar a instância do
tráfego, sem provocar reinícios em cascata.

Cada requisição verifica as dependências novamente, sem cache de resultados. O limite
total é `HEALTH_TIMEOUT_MS` (4000 ms por padrão, máximo 30000). Há no máximo duas
verificações simultâneas por instância; saturação também retorna 503. SQL usa timeout
de query de dois segundos. Uma operação de driver que não respeite interrupção pode
continuar até o timeout do próprio driver, mas a resposta HTTP não espera por ela.

Auth verifica as permissões de leitura das tabelas de autenticação no PostgreSQL,
um primary MongoDB de replica set e uma leitura em transação na coleção de refresh.
Não emite tokens nem altera dados. Backend verifica SQL, busca diretamente o JWKS
configurado e exige uma chave pública RSA utilizável para RS256, além de uma leitura
HTTP do ERP. As chamadas HTTP têm timeout de dois segundos e não seguem redirects.
`HEALTH_ERP_REQUIRED=true` é o padrão, independente de `ERP_SYNC_ENABLED`. Use false
somente em um deployment cujas funcionalidades realmente não dependam do ERP.

O endpoint é um smoke manual; sua execução não integra a suíte de testes nem é condição de aprovação do CI.

Smoke de ambiente a executar posteriormente: consultar a rota sem token, exigir 200 com dependências disponíveis e
503 ao interromper individualmente SQL, MongoDB, JWKS ou ERP necessário. Restaurar
cada dependência deve recuperar 200. Repetir pelo gateway e com contexto configurado.
JWT em cache não deve mascarar falha do JWKS. Complementar o health com login,
refresh, logout e consulta autenticada para validar o contrato funcional completo.
