# Authentication Service

Microservico de autenticacao reutilizavel construido com FastAPI. Projetado para ser plugado em qualquer projeto que precise de auth robusto, com sessoes opacas via cookie HTTP-only, CSRF, rate limiting por endpoint, soft delete e validacoes rigorosas seguindo recomendacoes OWASP e NIST.

> Projeto open-source extraido de um produto real. Sinta-se a vontade para clonar, adaptar e usar em qualquer projeto seu.

## Stack

| Componente | Tecnologia |
|---|---|
| Framework | FastAPI + Uvicorn |
| Banco | PostgreSQL 17 + SQLAlchemy 2 (async) |
| Cache / Sessoes | Redis 7 |
| Object Storage | MinIO |
| Migrations | Alembic |
| Hashing | Argon2id (argon2-cffi) |
| Deps | Poetry |
| Container | Docker Compose |

## Quickstart

```bash
# 1. Clone
git clone https://github.com/EduardoSA8006/authentication-service.git
cd authentication-service

# 2. Copie e configure o .env
cp .env.example .env
# Edite SECRET_KEY com um valor seguro:
#   openssl rand -hex 64

# 3. Suba tudo
docker compose up --build

# 4. Rode as migrations
docker compose exec api alembic upgrade head

# 5. Acesse
# API: http://127.0.0.1:8000/health
# Docs (apenas em DEBUG): http://127.0.0.1:8000/docs
# MinIO Console: http://127.0.0.1:9001
```

## Desenvolvimento local (sem Docker)

```bash
# Requer Python >=3.12 e Poetry instalado
poetry install

# Copie o .env e ajuste POSTGRES_HOST, REDIS_HOST para localhost
cp .env.example .env

# Rode
poetry run uvicorn app.main:app --reload
```

## Arquitetura

```
app/
├── core/                          # Infraestrutura — nenhuma feature importa de volta
│   ├── config.py                  #   Settings (Pydantic) + validacao de producao
│   ├── database.py                #   SQLAlchemy async engine + Base
│   ├── redis.py                   #   Conexao Redis
│   ├── security.py                #   Token opaco, CSRF HMAC, sessoes, cookies
│   ├── middleware.py              #   Rate limit, headers, size limit, session, CSRF
│   ├── exceptions.py              #   Hierarquia base de erros
│   └── error_handlers.py          #   Handlers globais registrados no app
├── shared/                        # Codigo reutilizado entre features
│   └── dependencies.py            #   get_current_session
├── features/                      # Feature-first — cada feature isolada
│   └── auth/
│       ├── models.py              #   User (SQLAlchemy)
│       ├── schemas.py             #   Request/Response (Pydantic)
│       ├── validators.py          #   Nome, email, senha, data de nascimento
│       ├── service.py             #   Logica de negocio
│       ├── router.py              #   Endpoints
│       ├── exceptions.py          #   Erros especificos da feature
│       └── rate_limit.py          #   Rate limit por endpoint
└── migrations/
    └── versions/
```

**Regra de dependencia:** `features/` -> `shared/` -> `core/` (nunca o contrario).

## Endpoints

### Auth (`/auth`)

| Metodo | Rota | Auth | Rate Limit | Descricao |
|---|---|---|---|---|
| POST | `/auth/register` | Nao | IP 5/min, Email 3/min | Criar conta |
| POST | `/auth/login` | Nao | IP 10/min, Email 5/5min | Login (set cookies) |
| POST | `/auth/logout` | Sim | IP 10/min | Logout (revoga token) |
| POST | `/auth/logout-all` | Sim | IP 10/min | Revoga todas as sessoes |
| POST | `/auth/verify-email` | Nao | IP 10/min | Verificar email |
| GET | `/auth/me` | Sim | -- | Dados do usuario |
| POST | `/auth/delete-account` | Sim | IP 3/min | Soft delete (7 dias) |

### Outros

| Metodo | Rota | Descricao |
|---|---|---|
| GET | `/health` | Health check |

## Modelo de Autenticacao

### Sessao opaca + CSRF

A autenticacao usa tokens opacos de 48 caracteres armazenados no Redis, nunca expostos ao JavaScript.

```
Browser                           Backend                         Redis
  │                                  │                               │
  │── POST /auth/login ──────────>   │                               │
  │                                  │── create_session() ────────>  │
  │                                  │<── token ──────────────────   │
  │<── Set-Cookie: session (httponly, strict) ──│                     │
  │<── Set-Cookie: csrf_token (lax, JS-readable)│                    │
  │                                  │                               │
  │── POST /auth/... ────────────>   │                               │
  │   Cookie: session=<token>        │── get_session(token) ──────>  │
  │   X-CSRF-Token: <hmac>           │── verify_csrf(token, hmac)    │
```

- **Session cookie**: `HttpOnly`, `Secure` (prod), `SameSite=Strict`
- **CSRF cookie**: `SameSite=Lax`, legivel por JS — frontend envia via header `X-CSRF-Token`
- **CSRF token**: `HMAC-SHA256(SECRET_KEY, session_token)` — vinculado criptograficamente a sessao

### Lifecycle do token

| Evento | Comportamento |
|---|---|
| **Expiracao absoluta** | Sessao morre apos `SESSION_TTL` (default 7 dias) |
| **Expiracao idle** | Sessao morre apos `SESSION_IDLE_TTL` (default 24h) de inatividade |
| **Rotacao** | Novo token gerado a cada `TOKEN_ROTATION_INTERVAL` (default 1h) |
| **Grace period** | Token antigo funciona por `TOKEN_ROTATION_GRACE` (default 60s), read-only |
| **Logout** | Token revogado instantaneamente no Redis |
| **Logout all** | Todas as sessoes do usuario deletadas atomicamente (Lua script) |

### User-Agent binding

Sessoes sao vinculadas ao User-Agent do navegador. Mudanca de UA invalida a sessao imediatamente.

## Seguranca

### Middleware stack (ordem de execucao)

```
Request → TrustedHost → SecurityHeaders → RateLimit → CORS → SizeLimit → Session → CSRF → Route
```

| Middleware | Funcao |
|---|---|
| **TrustedHost** | Rejeita requests com `Host` fora de `ALLOWED_HOSTS` |
| **SecurityHeaders** | `X-Content-Type-Options`, `X-Frame-Options`, `CSP`, `HSTS`, etc. |
| **RateLimit** | 100 req/min por IP via Redis (fail-closed: 503 se Redis cair, evita bypass via DoS) |
| **CORS** | Restrito a `ALLOWED_ORIGINS`, credentials habilitado |
| **SizeLimit** | Rejeita body >10MB (raw ASGI, verifica bytes reais, nao so Content-Length) |
| **Session** | Valida/rotaciona sessao, atualiza last_active, binding de UA |
| **CSRF** | Signed double-submit cookie para metodos nao-seguros |

### Headers de seguranca

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Cache-Control: no-store
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload  (quando HTTPS)
```

### Validacoes e anti-enumeracao (OWASP)

**Nome**
- 2-120 caracteres, minimo 2 palavras
- Aceita: letras Unicode, espacos, hifen, apostrofo, ponto
- Bloqueia: caracteres de controle, invisíveis, null bytes
- Formatacao automatica: `JOÃO DA SILVA` → `João da Silva`, `D'ÁVILA` → `D'Ávila`

**Email**
- Validado via `email-validator` (nao regex caseira)
- Normalizado para lowercase inteiro
- Preserva `+alias` e pontos
- Anti-enumeracao: mesma resposta neutra em register/login independente do email existir

**Senha (NIST SP 800-63B)**
- Minimo 8 caracteres, 1 maiuscula, 1 numero, 1 especial
- Blocklist de 100+ senhas comuns (password, 123456, qwerty, senha, admin, etc.)
- Deteccao de sequencias (abcd, 1234, aaaa)
- Deteccao contextual (partes do nome, email ou nome do sistema)
- Hash: **Argon2id** com rehash automatico em login se parametros mudarem

**Anti-enumeracao**
- Register: sempre retorna mensagem neutra, timing constante (Argon2 hash sempre computado)
- Login (email errado): roda Argon2 verify contra dummy hash → timing identico
- Login (senha errada): mesma mensagem generica
- Login (nao verificado): revela status apenas apos credenciais corretas

### Tratamento de erros

```
AppError (500)
├── BadRequestError (400)
│   └── InvalidVerificationTokenError
├── UnauthorizedError (401)
│   ├── InvalidCredentialsError
│   └── SessionExpiredError
├── ForbiddenError (403)
│   └── EmailNotVerifiedError
├── NotFoundError (404)
├── ConflictError (409)
├── RateLimitedError (429)
```

Formato padronizado de erro:

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Credenciais invalidas"
  }
}
```

Erros 500 em producao nunca expõem stack traces ou detalhes internos.

### Validacao de startup

Em modo producao (`DEBUG=false`), o servidor **recusa iniciar** se:
- `SECRET_KEY` ainda tem o valor placeholder
- `COOKIE_SECURE` esta `false`
- `ALLOWED_HOSTS` contem `localhost`
- `MINIO_SECURE` esta `false`

Docs (Swagger/ReDoc/OpenAPI) ficam **desabilitados** fora do modo DEBUG.

## Soft delete

Quando um usuario deleta a conta:

1. `deleted_at` recebe timestamp atual
2. Todas as sessoes sao revogadas instantaneamente
3. Login fica bloqueado
4. Apos 7 dias: hard delete automatico via background task (Redis lock para nao duplicar entre workers)

## Variaveis de ambiente

```bash
# Projeto
PROJECT_NAME=Authentication Service
DEBUG=true                    # false em producao

# PostgreSQL
POSTGRES_USER=auth
POSTGRES_PASSWORD=auth
POSTGRES_DB=auth_service
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
DB_ECHO=false                 # true para logar queries SQL

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=redis

# MinIO
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_SECURE=false            # true em producao

# Seguranca
SECRET_KEY=<obrigatorio>      # openssl rand -hex 64
ALLOWED_ORIGINS=["http://localhost:3000"]
ALLOWED_HOSTS=["localhost","127.0.0.1"]
TRUSTED_PROXY_IPS=["127.0.0.1","::1"]

# Rate Limiting
RATE_LIMIT_REQUESTS=100       # por IP, por minuto
RATE_LIMIT_WINDOW=60

# Sessao
SESSION_TTL=604800            # 7 dias
SESSION_IDLE_TTL=86400        # 24 horas
TOKEN_ROTATION_INTERVAL=3600  # 1 hora
TOKEN_ROTATION_GRACE=60       # segundos
COOKIE_SECURE=false           # true em producao
```

## Deploy em producao

```bash
# 1. Gere um SECRET_KEY seguro
openssl rand -hex 64

# 2. Configure o .env de producao
DEBUG=false
SECRET_KEY=<valor_gerado>
COOKIE_SECURE=true
MINIO_SECURE=true
ALLOWED_HOSTS=["seu-dominio.com"]
ALLOWED_ORIGINS=["https://seu-dominio.com"]
POSTGRES_PASSWORD=<senha_forte>
REDIS_PASSWORD=<senha_forte>
MINIO_ACCESS_KEY=<usuario_forte>
MINIO_SECRET_KEY=<senha_forte>

# 3. Suba com o compose de producao
docker compose -f docker-compose.prod.yml up -d --build

# 4. Rode migrations
docker compose -f docker-compose.prod.yml exec api alembic upgrade head
```

Todos os servicos ficam em `127.0.0.1` — nada exposto para a rede. O frontend na mesma VPS acessa o backend via localhost. Apenas o frontend (nginx) deve ter porta aberta.

### Invariantes operacionais

Coisas que o código assume e quebram silenciosamente se violadas em produção:

- **`TRUSTED_PROXY_IPS` precisa conter o IP do proxy como visto do container**, não `127.0.0.1`. Se o API roda em um container e o nginx/sidecar em outro (rede overlay Docker, ex.: `172.18.0.0/16`), o peer recebido pelo ASGI é o IP do proxy no overlay — `127.0.0.1` nessa lista faz `get_client_ip` ignorar `X-Forwarded-For` e usar o IP do proxy. Rate-limit, lockout e logs passam a indexar por proxy, não pelo cliente real. Validar pós-deploy com uma request externa + `docker logs api` confirmando que o IP logado é o do cliente, não o do nginx.
- **Session cookie é `SameSite=Strict` por design.** Links em email (verify-email, reset-password) que abrem o frontend cold-start não carregam o cookie de sessão; os endpoints desses fluxos não exigem sessão, então funciona. Se um futuro flow autenticado for disparado por clique-em-email no cold-start, ele precisa ser redesenhado (rota intermediária que pede login novamente ou troca para `Lax` — NÃO trocar sem revisitar o modelo de ameaça do CSRF).
- **Troca de `COOKIE_DOMAIN` em produção requer janela de migração.** Alterar `null → .example.com` (ou vice-versa) faz o `delete_cookie` novo não apagar cookies emitidos sob a config antiga — browser fica com sessão fantasma até o TTL expirar (até 7 dias). Mitigação: durante a janela, emitir `delete_cookie` nas duas configs, ou renomear o cookie (`SESSION_COOKIE_NAME`) pra forçar re-login global.
- **Session cookie não usa `Partitioned` (CHIPS).** O serviço é first-party (frontend bate direto no API); cookies third-party em contexto `<iframe>` embedado por parceiro nem sequer chegariam com `SameSite=Strict`. Se o produto vier a embedar o frontend em iframe de partner, revisar os dois flags em conjunto (`Partitioned` + relaxar `SameSite` para `None`) — decisão conjunta, não isolada.
- **Política de senha NÃO segue NIST SP 800-63B §5.1.1.2.** `validate_password` exige complexidade (upper + digit + special) além de length/HIBP/common/sequential/contextual. NIST desencoraja composition rules porque empurram usuários para `Password1!` (passa rules, é fraco). Mantido por decisão de produto atual (cobre requisitos de auditoria que ainda citam SP 800-63A antigo). Ao relaxar, manter o mínimo de 10 chars + HIBP/common/contextual — a checagem de breach é o filtro que agrega valor real.
- **`/readyz` não pode ser exposto publicamente.** É exempt de rate-limit (LB probes não podem receber 429, senão o serviço vira unhealthy sob carga) e faz `ping` no Redis + `SELECT 1` no Postgres a cada request. Atacante spammando `/readyz` gera load real nas dependências. Expor só em rede interna do LB/ingress; `/livez` (sem check de deps) pode ser externo se necessário.
- **CSRF cookie é `HttpOnly=false` (double-submit requer leitura via JS).** Se o frontend sofrer XSS, atacante lê `csrf_token` e forja requests state-changing autenticados. Mitigação depende de CSP restritivo NO FRONTEND (não neste backend — o CSP daqui só protege responses deste serviço, que são JSON). O frontend deve declarar `default-src 'self'; script-src 'self'` no mínimo, sem `'unsafe-inline'`/`'unsafe-eval'`. Sem isso, o modelo de CSRF cai para "best-effort" em caso de XSS do FE.
- **CAPTCHA é enviado via header `X-Captcha-Token`, não no body.** Habilitado no CORS `allow_headers`. Frontend obtém token do Cloudflare Turnstile (`cf-turnstile-response` no widget) e envia como `X-Captcha-Token` no login — o backend não espera o nome nativo do provider. Documentação de integração precisa refletir isso.

## Integracao com frontend

O frontend precisa:

1. **Login**: `POST /auth/login` com `{email, password}`. Os cookies sao setados automaticamente pelo browser.

2. **Requests autenticados**: Ler o cookie `csrf_token` (nao e HTTP-only) e enviar em cada request nao-GET:
   ```javascript
   const csrfToken = document.cookie
     .split('; ')
     .find(row => row.startsWith('csrf_token='))
     ?.split('=')[1];

   fetch('/auth/me', {
     credentials: 'include',
     headers: { 'X-CSRF-Token': csrfToken },
   });
   ```

3. **Logout**: `POST /auth/logout` — cookies sao limpos na resposta.

## Adicionando novas features

Crie uma pasta em `app/features/<nome>/` com:

```
app/features/<nome>/
├── __init__.py
├── models.py        # SQLAlchemy models
├── schemas.py       # Pydantic request/response
├── service.py       # Logica de negocio
├── router.py        # Endpoints
├── exceptions.py    # Erros especificos (herdam de core/exceptions.py)
└── rate_limit.py    # Rate limits especificos (se necessario)
```

Registre o router em `app/main.py`:
```python
from app.features.<nome>.router import router as <nome>_router
app.include_router(<nome>_router)
```

## Testes

A suite roda contra serviços reais (Postgres + Redis + MailHog) com rollback transacional por teste e `FLUSHDB` para isolamento. Coverage mínima de 85% enforçada.

```bash
# 1. Subir serviços de suporte
docker compose up -d postgres redis mailhog

# 2. Criar banco de teste + migrations (idempotente)
poetry run python tests/setup_db.py

# 3. Rodar suite completa
poetry run pytest

# Rodar só um nível
poetry run pytest tests/unit/          # ~1s
poetry run pytest tests/integration/   # ~5s
poetry run pytest tests/e2e/           # ~3s

# Rodar teste específico
poetry run pytest tests/unit/features/auth/test_validators.py::TestPassword -v

# Coverage HTML local
poetry run pytest --cov-report=html
xdg-open htmlcov/index.html
```

CI em GitHub Actions (`.github/workflows/ci.yml`) roda a mesma suite em cada PR/push contra `main`, com serviços injetados via `services:` do workflow.

## Contribuindo

Pull requests sao bem-vindos. Para mudancas grandes, abra uma issue primeiro para discutirmos o que voce gostaria de mudar.

Antes de enviar um PR:

```bash
poetry run ruff check .
poetry run mypy app/
poetry run pytest
```

Hook local de secrets (evita vazar `.env` via `git add -A`):

```bash
pipx install pre-commit
pre-commit install
```

O hook roda gitleaks em cada commit. O mesmo scan tambem roda em CI, mas so detecta apos push — o hook local impede que o secret saia da maquina.

## Licenca

Licenciado sob qualquer uma das licencas abaixo, a sua escolha:

- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE) ou <http://www.apache.org/licenses/LICENSE-2.0>)
- **MIT License** ([LICENSE-MIT](LICENSE-MIT) ou <https://opensource.org/licenses/MIT>)

A Apache-2.0 inclui concessao explicita de patentes; a MIT e mais simples e curta. Voce pode usar o codigo sob os termos da que preferir.

### Contribuicoes

Salvo declaracao explicita em contrario, qualquer contribuicao intencionalmente submetida para inclusao neste projeto por voce, conforme definido na Apache-2.0, sera dual-licenciada como acima, sem quaisquer termos ou condicoes adicionais.
