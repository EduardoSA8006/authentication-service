# Email Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implementar envio de email transacional de verificação após `/auth/register` + endpoint `POST /auth/resend-verification`. Fecha BAIXA-04 da auditoria de segurança.

**Architecture:** Módulo novo `core/email.py` (infra transversal) com Jinja2 Environment module-level e client `aiosmtplib` por envio (sem pool). Register e resend disparam `asyncio.create_task(send_verification_email(...))` fire-and-forget para preservar timing constante da resposta HTTP. MailHog em dev para paridade com SMTP real sem depender de provedor externo.

**Tech Stack:** FastAPI 0.135+, Python 3.12+, aiosmtplib 3.0+, Jinja2 3.1+, PostgreSQL, Redis 7.4+, MailHog v1 (dev only).

**Spec:** `docs/superpowers/specs/2026-04-16-email-verification-design.md`

---

## Preflight

**Antes de executar qualquer task**, garantir que:

### 1. Working tree limpo E com correções de segurança da rodada 2 commitadas

```bash
cd /home/eduardo8006/Documentos/projetos/authentication-service
git status --short
```

Expected: saída vazia.

**Importante:** este plano assume que as seguintes mudanças já estão commitadas:
- `POSTGRES_SSL` e `REDIS_TLS` settings em `config.py` (Task 3 Step 2 referencia-as como ponto de inserção)
- CSRF middleware exigindo `Origin`/`Referer` em POST sem autenticação (Task 13 usa `-H 'Origin: http://localhost:3000'` nos curls)
- `_check_origin()` helper em `middleware.py`
- Todas as outras 12 correções da auditoria (ALTA-01 a BAIXA-07)

Se houver modificações uncommitted da rodada de segurança, commitar primeiro usando a mensagem previamente aprovada:
```
fix(security): harden auth against HashDoS, Login CSRF, TOCTOU, and 12 other audit findings
```

Verificar que os settings esperados existem:
```bash
grep -c "POSTGRES_SSL\|REDIS_TLS" app/core/config.py
```
Expected: `≥4` (2 definitions + 2 validator checks)

### 2. Ferramentas

- `docker --version` (necessário para MailHog)
- `poetry --version` (necessário para deps)
- `nc` disponível (usado no healthcheck do mailhog)

### 3. `.env` local contém todos os settings obrigatórios

```bash
grep -c "SECRET_KEY\|ALLOWED_HOSTS" .env
```
Expected: `≥2`

Se o `.env` não existir ainda, copiar de `.env.example`:
```bash
cp .env.example .env
```

---

## File Structure

Mapa completo do que cada arquivo faz e por quê.

### Arquivos NOVOS

| Arquivo | Responsabilidade única |
|---|---|
| `app/core/email.py` | SMTP client + Jinja2 env + `send_email()` + `send_verification_email()` + `_hash_email()` para logs. Única entrada para envio de email no sistema. |
| `app/core/templates/emails/verification.html` | Template HTML do email de verificação (inline-styled, compatível com Gmail/Outlook/iOS Mail) |
| `app/core/templates/emails/verification.txt` | Template texto (multipart/alternative fallback) |

### Arquivos MODIFICADOS

| Arquivo | Mudança | Motivo |
|---|---|---|
| `pyproject.toml` | +2 deps | aiosmtplib, jinja2 |
| `app/core/config.py` | +7 settings, +4 warnings em prod | Config SMTP + FRONTEND_URL |
| `app/features/auth/schemas.py` | +`ResendVerificationRequest` | Novo endpoint precisa de schema |
| `app/features/auth/rate_limit.py` | +2 constantes | Rate limits para resend |
| `app/features/auth/service.py` | Dispatch de email em register; nova função `resend_verification_email` | Fire-and-forget + anti-enum no resend |
| `app/features/auth/router.py` | +endpoint `/auth/resend-verification` | Expor resend |
| `docker-compose.yml` | +serviço `mailhog` | Dev UX |
| `.env.example` | +8 vars | Documentar config nova |

### Princípio de reuso (nada reimplementado)

| Item reusado | De onde vem |
|---|---|
| `validate_and_normalize_email` | `app/features/auth/validators.py` |
| `check_rate_limit` | `app/features/auth/rate_limit.py` |
| `_get_client_ip` | `app/core/middleware.py` |
| `_create_verification_token`, `_get_user_by_email` | `app/features/auth/service.py` |
| `MessageResponse` | `app/features/auth/schemas.py` |
| Padrão HMAC | `app/core/security.py::generate_csrf_token` |

---

## Tasks

### Task 1: Adicionar dependências (aiosmtplib + jinja2)

**Files:**
- Modify: `pyproject.toml`
- Regenerate: `poetry.lock`

- [ ] **Step 1: Adicionar deps no `pyproject.toml`**

Abrir `pyproject.toml`. No bloco `dependencies = [`, adicionar duas linhas antes do `]` de fechamento (depois da última dep atual `argon2-cffi`):

```toml
    "argon2-cffi (>=25.1.0,<26.0.0)",
    "aiosmtplib (>=3.0.2,<4.0.0)",
    "jinja2 (>=3.1.4,<4.0.0)"
]
```

(Note a vírgula após `argon2-cffi` — antes ela era a última dep, agora precisa de vírgula)

- [ ] **Step 2: Atualizar lock file**

Run: `poetry lock --no-update`
Expected: saída mostra resolução dos novos pacotes sem alterar deps existentes

- [ ] **Step 3: Instalar deps**

Run: `poetry install --no-root`
Expected: `Installing aiosmtplib (3.0.x)` e `Installing jinja2 (3.1.x)` ou similar

- [ ] **Step 4: Verificar imports**

Run: `poetry run python -c "import aiosmtplib, jinja2; print('aiosmtplib', aiosmtplib.__version__, '| jinja2', jinja2.__version__)"`
Expected: imprime versões, sem erro de import

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml poetry.lock
git commit -m "$(cat <<'EOF'
chore: add aiosmtplib and jinja2 deps

Prepares groundwork for email verification feature.
Spec: docs/superpowers/specs/2026-04-16-email-verification-design.md
EOF
)"
```

---

### Task 2: Adicionar MailHog ao docker-compose.yml (dev)

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Adicionar serviço `mailhog`**

Abrir `docker-compose.yml`. Adicionar o serviço mailhog **depois** do serviço `minio` e **antes** do bloco `volumes:`. O arquivo deve ficar:

```yaml
  minio:
    image: minio/minio:RELEASE.2025-04-08T15-41-24Z
    command: server /data --console-address ":9001"
    ports:
      - "127.0.0.1:9000:9000"
      - "127.0.0.1:9001:9001"
    environment:
      MINIO_ROOT_USER: ${MINIO_ACCESS_KEY:-minioadmin}
      MINIO_ROOT_PASSWORD: ${MINIO_SECRET_KEY:-minioadmin}
    volumes:
      - minio_data:/data

  mailhog:
    image: mailhog/mailhog:v1.0.1
    ports:
      - "127.0.0.1:8025:8025"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "1025"]
      interval: 10s
      timeout: 3s
      retries: 3

volumes:
  postgres_data:
  redis_data:
  minio_data:
```

- [ ] **Step 2: Adicionar `mailhog` ao `depends_on` do `api`**

No serviço `api`, modificar o `depends_on` para incluir mailhog:

```yaml
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      minio:
        condition: service_started
      mailhog:
        condition: service_healthy
```

- [ ] **Step 3: Validar compose file**

Run: `docker compose config > /dev/null && echo OK`
Expected: `OK` (syntax válida)

- [ ] **Step 4: Subir mailhog isoladamente pra testar**

Run: `docker compose up -d mailhog`
Expected: container inicia

- [ ] **Step 5: Verificar UI acessível**

Run: `curl -sf http://127.0.0.1:8025/ | head -1`
Expected: saída HTML não-vazia (ex: `<!DOCTYPE html>`)

- [ ] **Step 6: Parar mailhog**

Run: `docker compose stop mailhog`

- [ ] **Step 7: Commit**

```bash
git add docker-compose.yml
git commit -m "$(cat <<'EOF'
chore(docker): add mailhog service to dev compose

Captures outgoing email in dev for manual verification of the
upcoming email verification flow. UI at http://localhost:8025.
Not added to docker-compose.prod.yml — production uses real SMTP.
EOF
)"
```

---

### Task 3: Adicionar settings SMTP + FRONTEND_URL em config.py

**Files:**
- Modify: `app/core/config.py`

- [ ] **Step 1: Adicionar settings na classe `Settings`**

Abrir `app/core/config.py`. Localizar a seção `# Security` e adicionar um **novo bloco depois** das settings de Security (TRUSTED_PROXY_IPS, POSTGRES_SSL, REDIS_TLS). Inserir antes da seção `# Rate limiting`:

```python
    # Email / SMTP
    SMTP_HOST: str = "mailhog"
    SMTP_PORT: int = 1025
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_TLS: bool = False
    SMTP_FROM: str = "Authentication Service <noreply@localhost>"
    SMTP_TIMEOUT: int = 15  # segundos

    # Frontend URL (obrigatório — sem default. Pydantic falha se ausente.)
    FRONTEND_URL: str
```

- [ ] **Step 2: Adicionar warnings em `validate_settings_for_production`**

Localizar `validate_settings_for_production()`. Adicionar os warnings **depois** do check de `REDIS_TLS` e **antes** do check de `ALLOWED_HOSTS`:

```python
    if not settings.REDIS_TLS:
        warnings.append("REDIS_TLS is False — Redis connection is unencrypted")

    if settings.FRONTEND_URL.startswith("http://"):
        warnings.append("FRONTEND_URL uses http:// (not https://)")

    if "localhost" in settings.FRONTEND_URL:
        warnings.append("FRONTEND_URL contains 'localhost'")

    if settings.SMTP_HOST in {"mailhog", "localhost"}:
        warnings.append(f"SMTP_HOST is '{settings.SMTP_HOST}' — dev-only")

    if not settings.SMTP_TLS:
        warnings.append("SMTP_TLS is False — email sent in plaintext")

    if not settings.SMTP_PASSWORD:
        warnings.append("SMTP_PASSWORD is empty")

    if "localhost" in settings.ALLOWED_HOSTS:
```

(A última linha é a existente que marca o ponto de inserção; não duplicar)

- [ ] **Step 3: Atualizar `.env` local (se existir)**

Run: `test -f .env && echo FRONTEND_URL=http://localhost:3000 >> .env || echo "sem .env, skip"`

Motivo: `FRONTEND_URL` não tem default, então o processo não sobe sem essa var. Em dev, apontar pro frontend local.

- [ ] **Step 4: Verificar que Settings instancia**

Run: `poetry run python -c "from app.core.config import settings; print(settings.SMTP_HOST, settings.FRONTEND_URL)"`
Expected: `mailhog http://localhost:3000` (ou o que estiver no .env)

Se der `ValidationError: FRONTEND_URL Field required`, significa que o `.env` não tem a var — rodar Step 3.

- [ ] **Step 5: Ruff check**

Run: `poetry run ruff check app/core/config.py`
Expected: `All checks passed!`

- [ ] **Step 6: Commit**

```bash
git add app/core/config.py .env.example
git commit -m "$(cat <<'EOF'
feat(config): add SMTP and FRONTEND_URL settings

Adds SMTP_HOST/PORT/USER/PASSWORD/TLS/FROM/TIMEOUT and required
FRONTEND_URL. Production validator warns on plaintext SMTP,
empty password, http:// frontend, mailhog/localhost as host.

Part of email verification feature.
EOF
)"
```

(Se `.env.example` ainda não foi modificado, vai para o próximo task; `git add` apenas do `config.py`)

---

### Task 4: Atualizar `.env.example` com vars de email

**Files:**
- Modify: `.env.example`

- [ ] **Step 1: Adicionar settings**

Abrir `.env.example`. Adicionar **ao final** do arquivo (depois de `COOKIE_SECURE=false`):

```env

# SMTP (defaults apontam pra mailhog em dev)
SMTP_HOST=mailhog
SMTP_PORT=1025
SMTP_USER=
SMTP_PASSWORD=
SMTP_TLS=false
SMTP_FROM="Authentication Service <noreply@localhost>"
SMTP_TIMEOUT=15

# Frontend URL (obrigatório — onde está a página de verify-email)
FRONTEND_URL=http://localhost:3000
```

- [ ] **Step 2: Verificar diff esperado**

Run: `git diff .env.example | head -30`
Expected: diff mostra apenas as 10 linhas adicionadas (incluindo linha em branco)

- [ ] **Step 3: Commit**

```bash
git add .env.example
git commit -m "$(cat <<'EOF'
docs(env): document SMTP and FRONTEND_URL settings

Adds defaults pointing at mailhog for dev parity.
FRONTEND_URL has no default — must be set explicitly.
EOF
)"
```

---

### Task 5: Criar templates de email

**Files:**
- Create: `app/core/templates/emails/verification.html`
- Create: `app/core/templates/emails/verification.txt`

- [ ] **Step 1: Criar diretório**

Run: `mkdir -p app/core/templates/emails`
Expected: diretório criado (ou já existente)

- [ ] **Step 2: Criar `verification.html`**

Criar arquivo `app/core/templates/emails/verification.html` com conteúdo:

```html
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="color-scheme" content="light dark">
  <title>Confirme seu email</title>
</head>
<body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f5f5;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f5f5f5;">
    <tr>
      <td align="center" style="padding:40px 16px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;background:#ffffff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.04);">
          <tr>
            <td style="padding:32px 32px 16px;">
              <h1 style="margin:0;font-size:22px;font-weight:600;color:#111827;line-height:1.3;">
                Olá, {{ name }}
              </h1>
            </td>
          </tr>
          <tr>
            <td style="padding:0 32px;">
              <p style="margin:0 0 16px;font-size:15px;line-height:1.6;color:#374151;">
                Recebemos uma solicitação para criar uma conta com este email. Clique no botão abaixo para confirmar:
              </p>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:16px 32px 24px;">
              <a href="{{ link }}"
                 style="display:inline-block;padding:12px 28px;background:#2563eb;color:#ffffff;text-decoration:none;border-radius:6px;font-size:15px;font-weight:500;">
                Confirmar email
              </a>
            </td>
          </tr>
          <tr>
            <td style="padding:0 32px 24px;">
              <p style="margin:0 0 8px;font-size:13px;color:#6b7280;line-height:1.5;">
                Ou copie e cole este endereço no navegador:
              </p>
              <p style="margin:0;font-size:12px;color:#4b5563;word-break:break-all;">
                <a href="{{ link }}" style="color:#2563eb;text-decoration:underline;">{{ link }}</a>
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:16px 32px 32px;border-top:1px solid #e5e7eb;">
              <p style="margin:0;font-size:12px;color:#9ca3af;line-height:1.5;">
                Este link expira em 24 horas. Se você não criou esta conta, ignore este email — nenhuma ação é necessária.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
```

- [ ] **Step 3: Criar `verification.txt`**

Criar arquivo `app/core/templates/emails/verification.txt` com conteúdo:

```
Olá, {{ name }}

Recebemos uma solicitação para criar uma conta com este email.
Clique no link abaixo para confirmar:

{{ link }}

Este link expira em 24 horas. Se você não criou esta conta, ignore
este email — nenhuma ação é necessária.
```

- [ ] **Step 4: Verificar que Jinja consegue carregar**

Run:
```bash
poetry run python -c "
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
env = Environment(
    loader=FileSystemLoader(Path('app/core/templates/emails')),
    autoescape=select_autoescape(['html']),
)
html = env.get_template('verification.html').render(name='João', link='https://example.com/verify?token=XXX')
txt = env.get_template('verification.txt').render(name='João', link='https://example.com/verify?token=XXX')
print('HTML OK, length:', len(html))
print('TXT OK, length:', len(txt))
print('XSS test:', 'script' in env.get_template('verification.html').render(name='<script>alert(1)</script>', link='x'))
"
```

Expected:
```
HTML OK, length: 2200+
TXT OK, length: 200+
XSS test: True
```

(O `True` no XSS test é esperado — o texto literal "script" aparece, mas HTML-escaped como `&lt;script&gt;`, não executável)

- [ ] **Step 5: Verificar escape em detalhe**

Run:
```bash
poetry run python -c "
from jinja2 import Environment, FileSystemLoader, select_autoescape
env = Environment(loader=FileSystemLoader('app/core/templates/emails'), autoescape=select_autoescape(['html']))
html = env.get_template('verification.html').render(name='<script>alert(1)</script>', link='x')
print('ESCAPED OK' if '&lt;script&gt;' in html and '<script>' not in html else 'ESCAPE FAIL')
"
```

Expected: `ESCAPED OK`

- [ ] **Step 6: Commit**

```bash
git add app/core/templates/
git commit -m "$(cat <<'EOF'
feat(templates): add verification email html and txt templates

Inline-styled HTML with table-based layout for broad email
client compatibility (Gmail, Outlook, iOS Mail). Plain text
fallback for multipart/alternative. Jinja2 autoescape prevents
XSS via user-controlled name field.
EOF
)"
```

---

### Task 6: Criar módulo `core/email.py`

**Files:**
- Create: `app/core/email.py`

- [ ] **Step 1: Criar arquivo com implementação completa**

Criar `app/core/email.py`:

```python
import hashlib
import hmac
import logging
from email.message import EmailMessage
from pathlib import Path

import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import settings

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates" / "emails"

_jinja_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
    auto_reload=settings.DEBUG,
    enable_async=False,
)

# SMTP header injection guard (RFC 5321 §4.1.1.2)
_FORBIDDEN_HEADER_CHARS = frozenset({"\r", "\n", "\x00"})


# ---------------------------------------------------------------------------
# Low-level
# ---------------------------------------------------------------------------

async def send_email(
    to: str,
    subject: str,
    template_name: str,
    context: dict,
) -> None:
    """Render multipart email and send via SMTP.

    Renders {template_name}.html (autoescape) + {template_name}.txt (raw)
    from core/templates/emails/. Raises on validation/render/SMTP errors.
    Callers em asyncio.create_task devem capturar exceptions.
    """
    # SMTP injection guard
    for field_name, value in (("to", to), ("subject", subject)):
        if any(c in _FORBIDDEN_HEADER_CHARS for c in value):
            raise ValueError(f"Invalid character in {field_name}")

    html_body = _jinja_env.get_template(f"{template_name}.html").render(**context)
    text_body = _jinja_env.get_template(f"{template_name}.txt").render(**context)

    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    await aiosmtplib.send(
        msg,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER or None,
        password=settings.SMTP_PASSWORD or None,
        start_tls=settings.SMTP_TLS,
        timeout=settings.SMTP_TIMEOUT,
    )


# ---------------------------------------------------------------------------
# High-level wrappers
# ---------------------------------------------------------------------------

async def send_verification_email(name: str, email: str, token: str) -> None:
    """Safe fire-and-forget wrapper. Catches and logs."""
    link = f"{settings.FRONTEND_URL.rstrip('/')}/verify-email?token={token}"
    try:
        await send_email(
            to=email,
            subject="Confirme seu email",
            template_name="verification",
            context={"name": name, "link": link},
        )
        logger.info("Verification email sent (hash=%s)", _hash_email(email))
    except Exception:
        logger.warning(
            "Failed to send verification email (hash=%s)",
            _hash_email(email),
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# Log hygiene
# ---------------------------------------------------------------------------

def _hash_email(email: str) -> str:
    """HMAC-SHA256(SECRET_KEY, email)[:16] — log correlation without leaking PII.
    Same pattern as core/security.py::generate_csrf_token."""
    return hmac.new(
        settings.SECRET_KEY.encode(),
        email.encode(),
        hashlib.sha256,
    ).hexdigest()[:16]
```

- [ ] **Step 2: Verificar que módulo carrega**

Run:
```bash
poetry run python -c "
from app.core.email import send_email, send_verification_email, _hash_email
print('module loads OK')
print('_hash_email test:', _hash_email('test@example.com'))
"
```

Expected: `module loads OK` + hash de 16 chars hex (ex: `a1b2c3d4e5f67890`)

- [ ] **Step 3: Testar SMTP injection guard**

Run:
```bash
poetry run python -c "
import asyncio
from app.core.email import send_email
try:
    asyncio.run(send_email('a\r\nBcc: evil@x', 'sub', 'verification', {'name':'n','link':'l'}))
    print('FAIL: should have raised')
except ValueError as e:
    print('OK:', e)
"
```

Expected: `OK: Invalid character in to`

- [ ] **Step 4: Ruff + mypy**

Run: `poetry run ruff check app/core/email.py`
Expected: `All checks passed!`

Run: `poetry run mypy app/core/email.py 2>&1 | grep -v "^$" | head -10`
Expected: nenhum erro novo (pode haver warnings pré-existentes do projeto; comparar com baseline se necessário)

- [ ] **Step 5: Teste end-to-end com MailHog**

Run: `docker compose up -d mailhog`

Run:
```bash
poetry run python -c "
import asyncio
from app.core.email import send_verification_email
asyncio.run(send_verification_email('João Silva', 'joao@test.com', 'abc123token'))
"
```

Expected: sem output (ou log INFO se logging configurado); sem exception

Run: `curl -s http://127.0.0.1:8025/api/v2/messages | python -c "import json,sys; d=json.load(sys.stdin); print('emails in MailHog:', d['total'])"`
Expected: `emails in MailHog: 1` (ou mais se já tinha)

Run: `docker compose stop mailhog`

- [ ] **Step 6: Commit**

```bash
git add app/core/email.py
git commit -m "$(cat <<'EOF'
feat(core): add email module (SMTP + Jinja2)

New core/email.py provides:
- send_email(to, subject, template, context) — low-level multipart sender
- send_verification_email(name, email, token) — fire-and-forget safe wrapper
- _hash_email(email) — HMAC-SHA256 for PII-free logs (same pattern as CSRF)

Uses aiosmtplib with per-send connection (no pool), Jinja2 env loaded
at module import, autoescape ON for html templates. SMTP header
injection guard rejects CRLF/null in to/subject.

Spec: docs/superpowers/specs/2026-04-16-email-verification-design.md
EOF
)"
```

---

### Task 7: Integrar send_verification_email no register_user

**Files:**
- Modify: `app/features/auth/service.py`

- [ ] **Step 1: Adicionar import no topo**

Abrir `app/features/auth/service.py`. Adicionar `asyncio` aos imports stdlib existentes e importar a função de email. No topo do arquivo, **depois** dos imports stdlib existentes e **antes** dos imports de `app.*`:

Localizar a seção de imports:
```python
import hashlib
import json
import logging
import secrets
from datetime import UTC, date, datetime, timedelta
```

Adicionar `asyncio`:
```python
import asyncio
import hashlib
import json
import logging
import secrets
from datetime import UTC, date, datetime, timedelta
```

Depois, na seção `from app.core.*`, adicionar import do email:

Localizar:
```python
from app.core.redis import get_redis
from app.core.security import (
    create_session,
    delete_all_user_sessions,
    delete_session,
)
```

Adicionar **logo acima** do `from app.core.security`:
```python
from app.core.email import _hash_email, send_verification_email
```

- [ ] **Step 2: Modificar assinatura e corpo de `register_user`**

Localizar a função `register_user` inteira (atualmente retorna `str | None`). Substituir toda a função pelo seguinte:

```python
async def register_user(
    name: str,
    email: str,
    password: str,
    date_of_birth: date,
    db: AsyncSession,
    request: Request,
) -> None:
    """Register a new user. Anti-enum: retorna silenciosamente se email existe."""
    # Always hash to keep constant timing regardless of email existence
    password_hash = _ph.hash(password)

    existing = await _get_user_by_email(email, db, include_deleted=True)
    if existing is not None:
        return

    user = User(
        name=name,
        email=email,
        password_hash=password_hash,
        date_of_birth=date_of_birth,
    )
    db.add(user)
    await db.flush()

    try:
        token = await _create_verification_token(str(user.id), user.email)
    except Exception:
        await db.rollback()
        raise

    await db.commit()

    # Fire-and-forget — preserva timing constante da resposta
    asyncio.create_task(send_verification_email(user.name, user.email, token))
```

Mudanças vs versão atual:
- Tipo de retorno: `str | None` → `None`
- `return None` no caminho "existing" vira `return` sem valor
- Nova linha `asyncio.create_task(...)` depois do `db.commit()`

- [ ] **Step 3: Verificar que router não depende do retorno**

Run: `grep -n "register_user" app/features/auth/router.py`
Expected: linha da chamada mostra algo como `await register_user(...)` SEM atribuição a variável. Se houver `token = await register_user(...)` ou similar, precisa ser ajustado no próximo task.

- [ ] **Step 4: Ruff + mypy**

Run: `poetry run ruff check app/features/auth/service.py`
Expected: `All checks passed!`

Run: `poetry run mypy app/features/auth/service.py 2>&1 | tail -5`
Expected: nenhum erro novo relativo ao baseline

- [ ] **Step 5: Smoke test — importação**

Run: `poetry run python -c "from app.features.auth.service import register_user; print('OK')"`
Expected: `OK`

- [ ] **Step 6: Commit**

```bash
git add app/features/auth/service.py
git commit -m "$(cat <<'EOF'
feat(auth): dispatch verification email after register

register_user now returns None (previously str | None) and spawns
asyncio.create_task(send_verification_email(...)) after db.commit().
Fire-and-forget preserves constant-time response (anti-enum).

Closes BAIXA-04: verification token was created but never sent.
EOF
)"
```

---

### Task 8: Ajustar router.register (se necessário)

**Files:**
- Modify: `app/features/auth/router.py` (possivelmente não é necessário)

- [ ] **Step 1: Inspecionar chamada atual**

Run: `grep -n -A 8 'async def register' app/features/auth/router.py`
Expected: encontrar o handler register com chamada tipo `await register_user(...)` (provavelmente sem atribuição — já era `None` descartado).

- [ ] **Step 2: Se houver atribuição ao retorno, remover**

Se a chamada estiver como:
```python
    token = await register_user(...)
```
ou
```python
    _ = await register_user(...)
```

Substituir por apenas:
```python
    await register_user(...)
```

Se já está sem atribuição (que é o caso provável após a rodada anterior), **este step é no-op**.

- [ ] **Step 3: Ruff**

Run: `poetry run ruff check app/features/auth/router.py`
Expected: `All checks passed!`

- [ ] **Step 4: Commit (skip se no-op)**

Se houve mudança:
```bash
git add app/features/auth/router.py
git commit -m "refactor(auth): drop discarded return from register_user call"
```

Se for no-op, pular este commit.

---

### Task 9: Adicionar `ResendVerificationRequest` schema

**Files:**
- Modify: `app/features/auth/schemas.py`

- [ ] **Step 1: Adicionar schema**

Abrir `app/features/auth/schemas.py`. Adicionar o novo schema **depois** de `VerifyEmailRequest` e **antes** de `UserResponse`:

```python
class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_and_normalize_email(v)


class UserResponse(BaseModel):
```

- [ ] **Step 2: Ruff**

Run: `poetry run ruff check app/features/auth/schemas.py`
Expected: `All checks passed!`

- [ ] **Step 3: Smoke test — validação**

Run:
```bash
poetry run python -c "
from app.features.auth.schemas import ResendVerificationRequest
ok = ResendVerificationRequest(email='Joao@Example.COM')
print('normalized:', ok.email)
try:
    ResendVerificationRequest(email='invalido')
    print('FAIL: should have raised')
except Exception as e:
    print('OK rejected:', type(e).__name__)
"
```

Expected:
```
normalized: joao@example.com
OK rejected: ValidationError
```

- [ ] **Step 4: Commit**

```bash
git add app/features/auth/schemas.py
git commit -m "$(cat <<'EOF'
feat(auth): add ResendVerificationRequest schema

Reuses validate_and_normalize_email validator — no duplication.
EOF
)"
```

---

### Task 10: Adicionar rate limits para resend

**Files:**
- Modify: `app/features/auth/rate_limit.py`

- [ ] **Step 1: Adicionar constantes**

Abrir `app/features/auth/rate_limit.py`. Localizar o bloco de constantes por endpoint (`REGISTER_IP`, `LOGIN_IP`, etc). Adicionar **depois** de `ME_IP`:

```python
REGISTER_IP = (5, 60)
REGISTER_EMAIL = (3, 60)
LOGIN_IP = (10, 60)
LOGIN_EMAIL = (5, 300)
VERIFY_IP = (10, 60)
LOGOUT_IP = (10, 60)
DELETE_ACCOUNT_IP = (3, 60)
ME_IP = (30, 60)
RESEND_IP = (3, 3600)
RESEND_EMAIL = (1, 600)
```

- [ ] **Step 2: Ruff**

Run: `poetry run ruff check app/features/auth/rate_limit.py`
Expected: `All checks passed!`

- [ ] **Step 3: Commit**

```bash
git add app/features/auth/rate_limit.py
git commit -m "$(cat <<'EOF'
feat(auth): add rate limits for resend-verification endpoint

RESEND_IP=(3, 3600) — 3 per hour per IP
RESEND_EMAIL=(1, 600) — 1 per 10 min per email

Conservative to prevent spam abuse; user can still request via
a fresh account if hit the limit.
EOF
)"
```

---

### Task 11: Implementar `resend_verification_email` no service

**Files:**
- Modify: `app/features/auth/service.py`

- [ ] **Step 1: Adicionar função**

Abrir `app/features/auth/service.py`. Localizar a seção `# Email verification` (onde está `_create_verification_token` e `verify_email`). Adicionar a nova função **depois** de `verify_email`:

```python
async def verify_email(token: str, db: AsyncSession) -> None:
    redis = get_redis()
    key = _verify_token_key(token)
    raw = await redis.getdel(key)
    if raw is None:
        raise InvalidVerificationTokenError

    data = json.loads(raw)
    user = await _get_user_by_id(data["user_id"], db)
    if user is None:
        raise InvalidVerificationTokenError

    user.is_verified = True
    await db.commit()


async def resend_verification_email(
    email: str, db: AsyncSession, request: Request,
) -> None:
    """Anti-enum: sempre no-op silencioso salvo se user existe + não-verificado."""
    user = await _get_user_by_email(email, db)

    if user is None:
        logger.info("Resend: email inexistente (hash=%s)", _hash_email(email))
        return

    if user.is_verified:
        logger.info("Resend: email já verificado (hash=%s)", _hash_email(email))
        return

    token = await _create_verification_token(str(user.id), user.email)
    asyncio.create_task(send_verification_email(user.name, user.email, token))
```

(A função `verify_email` acima é a versão já existente, mostrada como ponto de referência pra inserção. Não duplicá-la.)

- [ ] **Step 2: Ruff + mypy**

Run: `poetry run ruff check app/features/auth/service.py`
Expected: `All checks passed!`

Run: `poetry run mypy app/features/auth/service.py 2>&1 | tail -5`
Expected: nenhum erro novo relativo ao baseline

- [ ] **Step 3: Smoke test — import**

Run: `poetry run python -c "from app.features.auth.service import resend_verification_email; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add app/features/auth/service.py
git commit -m "$(cat <<'EOF'
feat(auth): add resend_verification_email service function

Anti-enum preserved: always returns silently. Logs with hashed email
in each no-op branch (inexistent, already-verified) for SIEM.

Reuses _get_user_by_email and _create_verification_token — no
duplication. Fires send_verification_email via create_task.
EOF
)"
```

---

### Task 12: Adicionar endpoint `POST /auth/resend-verification`

**Files:**
- Modify: `app/features/auth/router.py`

- [ ] **Step 1: Atualizar imports**

Abrir `app/features/auth/router.py`. Localizar o bloco `from app.features.auth.schemas import (`. Adicionar `ResendVerificationRequest`:

```python
from app.features.auth.schemas import (
    DeleteAccountRequest,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    ResendVerificationRequest,
    UserResponse,
    VerifyEmailRequest,
)
```

Localizar o bloco `from app.features.auth.service import (`. Adicionar `resend_verification_email`:

```python
from app.features.auth.service import (
    get_user_from_session,
    login_user,
    logout_all_sessions,
    logout_user,
    register_user,
    resend_verification_email,
    soft_delete_user,
    verify_email,
)
```

- [ ] **Step 2: Adicionar endpoint**

Localizar o endpoint `verify_email_endpoint`. Adicionar o novo endpoint **depois** dele e **antes** de `me`:

```python
@router.post("/verify-email", response_model=MessageResponse)
async def verify_email_endpoint(
    body: VerifyEmailRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    await check_rate_limit("verify:ip", ip, *rl.VERIFY_IP)

    await verify_email(body.token, db)
    return MessageResponse(message="Email verificado com sucesso")


@router.post("/resend-verification", response_model=MessageResponse)
async def resend_verification(
    body: ResendVerificationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    await check_rate_limit("resend:ip", ip, *rl.RESEND_IP)
    await check_rate_limit("resend:email", body.email, *rl.RESEND_EMAIL)
    await resend_verification_email(body.email, db, request)
    return MessageResponse(
        message="Se este email estiver disponível, você receberá um email de confirmação",
    )


@router.get("/me", response_model=UserResponse)
```

(O `verify_email_endpoint` acima é a versão já existente, mostrada como referência. Não duplicá-la. O mesmo para `me`.)

- [ ] **Step 3: Ruff**

Run: `poetry run ruff check app/features/auth/router.py`
Expected: `All checks passed!`

- [ ] **Step 4: Smoke test — rota registrada**

Run:
```bash
poetry run python -c "
from app.main import app
routes = [r.path for r in app.routes]
print('resend route present:', '/auth/resend-verification' in routes)
"
```

Expected: `resend route present: True`

- [ ] **Step 5: Commit**

```bash
git add app/features/auth/router.py
git commit -m "$(cat <<'EOF'
feat(auth): add POST /auth/resend-verification endpoint

Rate-limited (IP 3/h, email 1/10min) and anti-enum (always returns
neutral MessageResponse). Delegates to resend_verification_email
in service layer.

Completes email verification UX loop — users who don't receive
the initial email can request a new one.
EOF
)"
```

---

### Task 13: Verificação end-to-end via MailHog

**Files:** nenhum (só verificação).

Esta task segue o §9 do spec. Todos os passos abaixo devem passar.

- [ ] **Step 1: Subir stack completa**

Run: `docker compose up --build -d`
Expected: todos os 5 serviços (api, postgres, redis, minio, mailhog) healthy após ~30s.

Verificar:
```bash
docker compose ps --format "{{.Service}}: {{.Status}}"
```

Expected: todos com `Up ... (healthy)` ou `Up ... (running)`

- [ ] **Step 2: Rodar migrations**

Run: `docker compose exec api alembic upgrade head`
Expected: `INFO [alembic.runtime.migration] Running upgrade...` ou "already at head"

- [ ] **Step 3: Register user válido**

Run:
```bash
curl -s -X POST http://127.0.0.1:8000/auth/register \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{
    "name": "João Silva",
    "email": "joao@test.com",
    "password": "SenhaForte@2026",
    "date_of_birth": "1990-01-01"
  }' | head -c 200
```

Expected: `{"message":"Se este email estiver disponível..."}`

- [ ] **Step 4: Verificar email no MailHog UI**

Run: `curl -s http://127.0.0.1:8025/api/v2/messages | python -c "import json,sys; d=json.load(sys.stdin); print('total:', d['total']); print('subject:', d['items'][0]['Content']['Headers']['Subject'][0] if d['total'] else 'none')"`
Expected:
```
total: 1
subject: Confirme seu email
```

- [ ] **Step 5: Abrir UI no browser**

Run: `xdg-open http://127.0.0.1:8025/ 2>/dev/null || echo "abrir manualmente: http://127.0.0.1:8025/"`

Verificar visualmente:
- Email de `noreply@localhost` para `joao@test.com`
- Subject: "Confirme seu email"
- Botão azul "Confirmar email" visível
- Fallback URL visível e clicável
- Nome "João Silva" formatado corretamente

- [ ] **Step 6: Extrair token do link e verificar**

Run:
```bash
TOKEN=$(curl -s http://127.0.0.1:8025/api/v2/messages | python -c "
import json, sys, re
d = json.load(sys.stdin)
body = d['items'][0]['Content']['Body']
m = re.search(r'token=([A-Za-z0-9_-]+)', body)
print(m.group(1) if m else 'NOT_FOUND')
")
echo "Token: $TOKEN"

curl -s -X POST http://127.0.0.1:8000/auth/verify-email \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d "{\"token\":\"$TOKEN\"}"
```

Expected: `{"message":"Email verificado com sucesso"}`

- [ ] **Step 7: Token não funciona duas vezes (getdel atômico)**

Run:
```bash
curl -s -X POST http://127.0.0.1:8000/auth/verify-email \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d "{\"token\":\"$TOKEN\"}"
```

Expected: `{"error":{"code":"INVALID_VERIFICATION_TOKEN",...}}`

- [ ] **Step 8: Resend para email já verificado (anti-enum)**

Run:
```bash
curl -s -X POST http://127.0.0.1:8000/auth/resend-verification \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"email":"joao@test.com"}'
```

Expected: `{"message":"Se este email estiver disponível..."}` (mesma resposta)

Verificar nos logs:
```bash
docker compose logs api 2>&1 | grep "já verificado" | tail -1
```

Expected: linha como `Resend: email já verificado (hash=abcdef...)`

- [ ] **Step 9: Resend para email inexistente (anti-enum)**

Run:
```bash
curl -s -X POST http://127.0.0.1:8000/auth/resend-verification \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"email":"fake@nonexistent.com"}'
```

Expected: `{"message":"Se este email estiver disponível..."}` (mesma resposta)

Verificar nos logs:
```bash
docker compose logs api 2>&1 | grep "email inexistente" | tail -1
```

Expected: linha como `Resend: email inexistente (hash=abcdef...)`

- [ ] **Step 10: Rate limit do resend por email**

Registrar um novo user:
```bash
curl -s -X POST http://127.0.0.1:8000/auth/register \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"name":"Maria Santos","email":"maria@test.com","password":"OutraSenha@2026","date_of_birth":"1992-05-15"}'
```

Primeiro resend (deve funcionar):
```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8000/auth/resend-verification \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"email":"maria@test.com"}'
```

Expected: `200`

Segundo resend imediato (deve bloquear):
```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8000/auth/resend-verification \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"email":"maria@test.com"}'
```

Expected: `429`

- [ ] **Step 11: XSS test — nome com caracteres especiais**

(Note: nome passa pelo `validate_and_format_name` que rejeita `<` e `>`. Este teste confirma que a validação protege.)

Run:
```bash
curl -s -X POST http://127.0.0.1:8000/auth/register \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"name":"<script>alert(1)</script> Silva","email":"xss@test.com","password":"SenhaSegura@2026","date_of_birth":"1990-01-01"}' | head -c 200
```

Expected: `{"error":{"code":"VALIDATION_ERROR",...` (nome contém caracteres inválidos)

Se por algum motivo passar, verificar no MailHog que o template HTML escapou como `&lt;script&gt;`.

- [ ] **Step 12: SMTP failure resiliency**

Run: `docker compose stop mailhog`

Registrar novo user:
```bash
curl -s -w '\nHTTP: %{http_code}\n' -X POST http://127.0.0.1:8000/auth/register \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://localhost:3000' \
  -d '{"name":"Carlos Lima","email":"carlos@test.com","password":"SenhaForte@2026","date_of_birth":"1985-03-10"}'
```

Expected: `HTTP: 200` + mensagem neutra (usuário foi criado, email falhou silenciosamente)

Verificar log:
```bash
docker compose logs api 2>&1 | grep "Failed to send verification email" | tail -1
```

Expected: linha com warning

Restaurar mailhog:
```bash
docker compose start mailhog
```

- [ ] **Step 13: Cleanup e parar stack**

Run: `docker compose down -v`

(Flag `-v` remove volumes — dados de test descartados)

---

### Task 14: Regression check — ruff + mypy baseline

**Files:** nenhum (só verificação).

- [ ] **Step 1: Ruff em todo o projeto**

Run: `poetry run ruff check .`
Expected: `All checks passed!`

Se houver qualquer erro, investigar e corrigir no próprio arquivo afetado.

- [ ] **Step 2: Mypy baseline**

Run: `poetry run mypy app/ 2>&1 | grep "Found"`
Expected: `Found 9 errors in 4 files (checked 24 source files)` — **9 errors**, número idêntico ao baseline pré-mudanças.

(O número 24 source files sobe de 23 pra 24 por causa do novo `core/email.py`. Se o total de errors subir, é regressão nova.)

Se regressão detectada:
```bash
poetry run mypy app/ 2>&1 | grep "email.py\|service.py\|router.py\|config.py"
```

Investigar cada linha, corrigir no módulo afetado.

- [ ] **Step 3: Validar README não precisa update**

Run: `grep -c "verify-email\|resend" README.md`
Expected: ≥1 (README já menciona `/auth/verify-email`)

Note: README pode ser atualizado em commit separado se quiser adicionar seção sobre `/auth/resend-verification` e configuração de SMTP, mas **não é parte deste plan** (escopo mínimo).

- [ ] **Step 4: Final diff summary**

Run: `git log --oneline ^094b384 HEAD`
Expected: ver commits do plano, um por task (aproximadamente 11-13 commits dependendo de Tasks 8 ser no-op).

- [ ] **Step 5: Nenhum commit adicional necessário aqui**

Este task é só verificação; não produz commit próprio.

---

## Summary of commits produced

Expected commit sequence (em ordem):

1. `chore: add aiosmtplib and jinja2 deps`
2. `chore(docker): add mailhog service to dev compose`
3. `feat(config): add SMTP and FRONTEND_URL settings`
4. `docs(env): document SMTP and FRONTEND_URL settings`
5. `feat(templates): add verification email html and txt templates`
6. `feat(core): add email module (SMTP + Jinja2)`
7. `feat(auth): dispatch verification email after register`
8. (possivelmente no-op) `refactor(auth): drop discarded return from register_user call`
9. `feat(auth): add ResendVerificationRequest schema`
10. `feat(auth): add rate limits for resend-verification endpoint`
11. `feat(auth): add resend_verification_email service function`
12. `feat(auth): add POST /auth/resend-verification endpoint`

Total: 11-12 commits atômicos e focados.

## Rollback

Se precisar desfazer tudo (antes de merge):

```bash
git reset --hard 094b384   # ou o commit base do working tree limpo
```

Ou selectively:
```bash
git revert <commit-hash>   # por task
```

Ver §14 do spec para estratégias de rollback em produção sem revert de código.
