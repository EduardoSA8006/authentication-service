# Email Verification — Design Spec

**Data:** 2026-04-16
**Status:** Aprovado (brainstorming)
**Escopo:** Fecha BAIXA-04 da auditoria de segurança (token de verificação criado mas nunca enviado) e adiciona endpoint de resend.

---

## 1. Objetivo

Implementar envio de email transacional para o microserviço `authentication-service`, cobrindo:

1. Envio automático do link de verificação após `POST /auth/register`.
2. Novo endpoint `POST /auth/resend-verification` para reenviar o link caso o usuário não receba / perca o email.

Manter todas as garantias já estabelecidas (anti-enumeração, timing constante, feature-first, dual-licensed).

## 2. Decisões de design (tomadas no brainstorming)

| Decisão | Escolha | Racional |
|---|---|---|
| Provedor | SMTP configurável via `aiosmtplib` | Projeto é reusável; SMTP funciona com qualquer provedor (Gmail, SES, Postmark, Mailgun, self-hosted, MailHog em dev) |
| Timing | `asyncio.create_task()` fire-and-forget | Preserva constant-time do register; SMTP não bloqueia resposta |
| Dev UX | MailHog em `docker-compose.yml` | Paridade dev=prod com single code path; UI em `:8025` |
| URL do link | `FRONTEND_URL` obrigatório | Backend continua pure-API; frontend hospeda `/verify-email` |
| Template | Jinja2 + arquivos `.html`/`.txt` | Antecipa múltiplos tipos de email (password reset, welcome, etc.) |
| Escopo | Register + resend neste ciclo | Sem resend a feature fica incompleta (usuário travado se email falhar) |
| Modelo TLS | STARTTLS (porta 587) quando `SMTP_TLS=true` | Compatível com 90% dos provedores SaaS (SES, Postmark, Gmail); SMTPS (465) não suportado neste ciclo |
| Conexão SMTP | Nova conexão por envio (sem pool) | Volume esperado baixo (<100/h por instância); pool adiciona complexidade sem ganho mensurável |

## 3. Arquitetura

### Camadas (respeita feature-first → shared → core)

- `app/core/email.py` — infra transversal de SMTP + Jinja2
- `app/core/templates/emails/` — templates colocalizados com o código que os carrega
- `app/features/auth/*` — consumidores (register + resend)

Email é infra transversal (será reusado em password reset, welcome, notifications futuras) → fica em `core/`, nunca em `features/`.

### Fluxo — register

```
POST /auth/register
  ↓ (rate limit, validação schema, constant-time Argon2 hash)
register_user(...)
  ↓ db.flush() → _create_verification_token() → db.commit()
  ↓ asyncio.create_task(send_verification_email(...))   ← dispara e segue
return MessageResponse (neutra, tempo não depende de SMTP)
  ↓
[background] Jinja render html+txt → aiosmtplib.send → log
```

### Fluxo — resend

```
POST /auth/resend-verification {email}
  ↓ (rate limit IP 3/h + email 1/10min)
resend_verification_email(email, db, request)
  ↓
  se user existe E não verificado:
    _create_verification_token() → create_task(send_verification_email(...))
  se user existe E verificado:
    logger.info (hashed email) — não envia
  se user não existe:
    logger.info (hashed email) — não envia
  ↓
sempre: MessageResponse neutra
```

## 4. Componentes

### 4.1. Novo módulo `app/core/email.py`

**Imports necessários:**
```python
import hashlib
import hmac
import logging
from email.message import EmailMessage
from pathlib import Path

import aiosmtplib
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, select_autoescape

from app.core.config import settings
```

**Inicialização module-level (no import, uma vez por processo):**
```python
logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates" / "emails"

_jinja_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),   # bloqueia XSS via {{ name }}
    auto_reload=settings.DEBUG,               # off em prod (perf)
    enable_async=False,                        # render é CPU-bound, não benefit async
)

# Validação CRLF para prevenir SMTP header injection (RFC 5321 §4.1.1.2)
_FORBIDDEN_HEADER_CHARS = frozenset({"\r", "\n", "\x00"})
```

**Funções públicas:**

```python
async def send_email(
    to: str,
    subject: str,
    template_name: str,
    context: dict,
) -> None:
    """Envia email multipart (HTML + texto) via SMTP.

    Renders:
      - {template_name}.html     (autoescape ON)
      - {template_name}.txt      (sem escape; só texto)

    Raises:
      - ValueError se `to` ou `subject` contém CRLF (SMTP injection)
      - TemplateNotFound se qualquer template ausente
      - aiosmtplib.SMTPException / OSError em falha de rede

    Callers em asyncio.create_task devem envolver em try/except.
    """
    # 1. SMTP injection guard
    for field_name, value in (("to", to), ("subject", subject)):
        if any(c in _FORBIDDEN_HEADER_CHARS for c in value):
            raise ValueError(f"Invalid character in {field_name}")

    # 2. Render ambos templates
    html_body = _jinja_env.get_template(f"{template_name}.html").render(**context)
    text_body = _jinja_env.get_template(f"{template_name}.txt").render(**context)

    # 3. Build MIME
    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text_body)                  # text/plain (fallback)
    msg.add_alternative(html_body, subtype="html")  # text/html

    # 4. Send (nova conexão por envio; sem pool)
    await aiosmtplib.send(
        msg,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER or None,
        password=settings.SMTP_PASSWORD or None,
        start_tls=settings.SMTP_TLS,             # STARTTLS (porta 587)
        timeout=settings.SMTP_TIMEOUT,
    )


async def send_verification_email(name: str, email: str, token: str) -> None:
    """High-level wrapper seguro para fire-and-forget. Captura tudo."""
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


def _hash_email(email: str) -> str:
    """HMAC-SHA256(SECRET_KEY, email)[:16] — para logs sem vazar PII.
    Segue o mesmo padrão de generate_csrf_token em core/security.py."""
    return hmac.new(
        settings.SECRET_KEY.encode(),
        email.encode(),
        hashlib.sha256,
    ).hexdigest()[:16]
```

**Por que `EmailMessage` (stdlib) em vez de `MIMEMultipart`?**
Python 3.6+ fornece `email.message.EmailMessage` como a API moderna (substituindo as classes `MIME*` legadas). Mais simples, lida com encoding corretamente, e é recomendada pela doc oficial.

### 4.2. Templates

**`app/core/templates/emails/verification.html`:**

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

Decisões de design:
- **Inline CSS only**: Gmail, Outlook e muitos clients strippam `<style>` tags
- **`role="presentation"` em tables**: layout de email legado ainda é table-based pra compat com Outlook/Yahoo
- **`color-scheme`**: respeita dark mode no iOS/macOS Mail
- **`word-break:break-all`** no fallback URL: tokens longos quebram corretamente
- **Sem imagens/anexos**: reduz filter de spam + tempo de carregamento
- **Max-width 560px**: compatível com viewport de email clients móveis

**`app/core/templates/emails/verification.txt`:**

```
Olá, {{ name }}

Recebemos uma solicitação para criar uma conta com este email.
Clique no link abaixo para confirmar:

{{ link }}

Este link expira em 24 horas. Se você não criou esta conta, ignore
este email — nenhuma ação é necessária.
```

### 4.3. Settings novos em `app/core/config.py`

```python
# Email / SMTP
SMTP_HOST: str = "mailhog"
SMTP_PORT: int = 1025
SMTP_USER: str = ""
SMTP_PASSWORD: str = ""
SMTP_TLS: bool = False                    # STARTTLS — use True em prod (porta 587)
SMTP_FROM: str = "Authentication Service <noreply@localhost>"
SMTP_TIMEOUT: int = 15                    # segundos

# Obrigatório, sem default — Pydantic falha se não vier do env
FRONTEND_URL: str
```

Warnings em `validate_settings_for_production`:
- `FRONTEND_URL` começa com `http://` (não `https://`)
- `FRONTEND_URL` contém `localhost`
- `SMTP_HOST` ∈ `{"mailhog", "localhost"}`
- `SMTP_TLS` é `False`
- `SMTP_PASSWORD` vazio

### 4.4. `app/features/auth/schemas.py`

```python
class ResendVerificationRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_and_normalize_email(v)   # REUSA validator existente
```

### 4.5. `app/features/auth/rate_limit.py`

```python
RESEND_IP = (3, 3600)     # 3 por hora por IP
RESEND_EMAIL = (1, 600)   # 1 a cada 10 min por email
```

Usa `check_rate_limit()` existente — sem nova lógica.

### 4.6. `app/features/auth/service.py`

**Mudança de assinatura interna:** `register_user` passa a retornar `None` (em vez de `str | None`). Só é chamado de dentro do router deste projeto — não é API pública. O dispatch do email sai do router e vai pro service, depois do commit. Simétrico com `resend_verification_email`.

**Novo import no topo do arquivo:**
```python
import asyncio
from app.core.email import send_verification_email
```

**`register_user` atualizado (versão completa):**
```python
async def register_user(
    name: str,
    email: str,
    password: str,
    date_of_birth: date,
    db: AsyncSession,
    request: Request,
) -> None:
    """Register a new user. Anti-enum: returns silently whether email exists or not."""
    # Always hash to keep constant timing regardless of email existence
    password_hash = _ph.hash(password)

    existing = await _get_user_by_email(email, db, include_deleted=True)
    if existing is not None:
        return  # anti-enum: silent no-op

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

**Novo `resend_verification_email`:**
```python
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

Import adicional no topo do arquivo:
```python
from app.core.email import _hash_email, send_verification_email
```

Nota: `_hash_email` começa com underscore mas é intencionalmente importado cross-module aqui. Em vez de renomear para público (`hash_email`), mantemos o prefixo porque não é parte da API estável — é um utilitário de logs compartilhado entre `core/email.py` e um único caller em `features/auth/service.py`.

### 4.7. `app/features/auth/router.py`

- `register` — remove `await` no valor de retorno do `register_user`; simplifica.
- Novo endpoint:

```python
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
```

Adicionar o import da nova função no topo:
```python
from app.features.auth.service import (
    get_user_from_session,
    login_user,
    logout_all_sessions,
    logout_user,
    register_user,
    resend_verification_email,   # novo
    soft_delete_user,
    verify_email,
)
```

E o schema:
```python
from app.features.auth.schemas import (
    DeleteAccountRequest,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    ResendVerificationRequest,   # novo
    UserResponse,
    VerifyEmailRequest,
)
```

### 4.8. `docker-compose.yml` (dev) — serviço novo

```yaml
  mailhog:
    image: mailhog/mailhog:v1.0.1
    ports:
      - "127.0.0.1:8025:8025"      # só a UI; SMTP 1025 fica interno à rede Docker
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "1025"]
      interval: 10s
      timeout: 3s
      retries: 3
```

E adicionar no `depends_on` do serviço `api`:
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

`docker-compose.prod.yml` **não** ganha mailhog.

### 4.9. `.env.example`

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

### 4.10. `pyproject.toml`

```toml
"aiosmtplib (>=3.0.2,<4.0.0)",
"jinja2 (>=3.1.4,<4.0.0)",
```

### 4.11. Regras de formato de `FRONTEND_URL`

- **Esquema obrigatório**: `http://` em dev, `https://` em prod (warning se http em prod)
- **Sem trailing slash**: código usa `.rstrip('/')` antes de concatenar — tolera ambos
- **Sem path**: não é URL base com path (ex: `https://example.com/app`) — a página `/verify-email` é sempre assumida no root do frontend. Se precisar de subpath, criar setting separado `FRONTEND_VERIFY_PATH` no futuro.
- **Exemplo válido**: `https://app.example.com`, `http://localhost:3000`
- **Exemplo inválido**: `app.example.com` (sem scheme), `https://app.example.com/app/` (com path)

Validação sintática no Pydantic não é implementada neste ciclo (YAGNI — dev conhece o contrato). Pode ser adicionada via `HttpUrl` do Pydantic depois.

## 5. Reuso explícito (nada reimplementado)

| Item | Origem | Uso |
|---|---|---|
| `validate_and_normalize_email` | `features/auth/validators.py` | `ResendVerificationRequest` |
| `check_rate_limit` | `features/auth/rate_limit.py` | Novo endpoint resend |
| `_get_client_ip` | `core/middleware.py` | Novo endpoint resend |
| `get_redis` | `core/redis.py` | Reusado indiretamente via `_create_verification_token` |
| `_create_verification_token`, `_verify_token_key` | `features/auth/service.py` | Resend cria token igual ao register |
| `MessageResponse` | `features/auth/schemas.py` | Resposta do novo endpoint |
| `_get_user_by_email` | `features/auth/service.py` | `resend_verification_email` |
| `validate_and_format_name` | `features/auth/validators.py` | Nome já formatado chega no template |
| Padrão HMAC de logs | `core/security.py::generate_csrf_token` | `_hash_email()` segue o mesmo padrão |
| Pattern de warnings de produção | `core/config.py::validate_settings_for_production` | Adições seguem o mesmo formato |

## 6. Hierarquia de exceptions — respeitada

Nenhuma nova exception criada. Razões:

- **Falha SMTP em background:** captura/log em `send_verification_email`; nunca propaga (create_task é fire-and-forget).
- **Usuário não existe / já verificado no resend:** anti-enum proíbe diferenciar; service no-op silencioso.
- **Template faltando:** `TemplateNotFound` do Jinja crasha o lifespan no startup — correto (fail-fast).
- **SMTP injection em `to`/`subject`:** `ValueError` do `send_email`, capturado pelo wrapper. Como `to` e `subject` vêm de input já validado (email normalizado + string literal), na prática nunca dispara — é defense-in-depth.

`InvalidVerificationTokenError` existente em `features/auth/exceptions.py` continua atendendo o endpoint `verify-email`.

## 7. Segurança

### 7.1. Campos sensíveis — 100% via `.env`

| Campo | Default no código | Vem do env? | Observação |
|---|---|---|---|
| `SMTP_PASSWORD` | `""` | ✅ obrigatório em prod | Warning se vazio |
| `SMTP_USER` | `""` | ✅ | Muitos SMTPs exigem user+pass |
| `FRONTEND_URL` | **sem default** | ✅ obrigatório sempre | Pydantic falha no import se ausente |
| `SMTP_*` não sensíveis (host, port, from, tls, timeout) | defaults dev | ✅ overridables | |

Nada sensível (keys, passwords, tokens) aparece no código-fonte. Tokens de verificação são gerados dinamicamente via `secrets.token_urlsafe(32)` por chamada.

### 7.2. SMTP header injection (RFC 5321 §4.1.1.2)

Em `send_email`, campos `to` e `subject` são validados contra CRLF + null byte antes de entrarem no `EmailMessage`. Sem essa guarda, um atacante que controlasse um valor injetado poderia criar um email como:

```
To: victim@example.com\r\nBcc: attacker@evil.com
```

Atualmente `to` é sempre `user.email` (já normalizado pelo validator) e `subject` é sempre string literal. A guarda é defense-in-depth para quando novos callers surgirem.

### 7.3. XSS em templates HTML

`autoescape=select_autoescape(["html"])` no Jinja env garante que `{{ name }}` é HTML-escaped. Um nome contendo `<script>` vira `&lt;script&gt;` no email renderizado.

O template `.txt` não escapa (é texto), mas texto puro não é um vetor XSS.

### 7.4. Logs — zero PII

Emails nos logs sempre via `_hash_email()` (HMAC-SHA256 com `SECRET_KEY`, truncado em 16 chars). Rainbow table não reverte sem `SECRET_KEY`. 16 chars hex = 64 bits de entropia — suficiente pra correlacionar eventos, não pra enumerar.

### 7.5. TLS em trânsito

- `SMTP_TLS=true` usa STARTTLS (upgrade de conexão plaintext pra TLS na mesma porta, tipicamente 587)
- SMTPS (TLS implícito na porta 465) não é suportado neste ciclo. Adicionar setting `SMTP_SSL: bool` se necessário
- Certificado do servidor SMTP é validado por padrão pelo `aiosmtplib` (via `ssl.create_default_context()`)

### 7.6. Link token entropy

`_create_verification_token` usa `secrets.token_urlsafe(32)` → 32 bytes = **256 bits** de entropia. Impossível de brute-force (nem com 10^20 tentativas/segundo por 10^10 anos). Armazenado como `sha256(token)` no Redis (defense-in-depth se dump do Redis vazar).

### 7.7. Sanitização do `FRONTEND_URL`

`FRONTEND_URL` vem do ambiente (operador de deploy é quem configura). Se for mal-configurado (ex: `javascript:alert(1)`), o link no email seria quebrado. Nota: não é vetor de ataque porque o operador é trust boundary — mas Pydantic pode ganhar `HttpUrl` validation no futuro.

## 8. Edge cases

| Cenário | Comportamento |
|---|---|
| Anti-enum em register | Timing não depende de SMTP (create_task é não-blocking); resposta neutra |
| Anti-enum em resend | Mesmo rate limit pra existente/não-existente; timing difere ~1ms (SET Redis) dentro do ruído de rede |
| Falha SMTP em background | Loga com hash do email, não propaga. Usuário usa `/resend-verification` |
| Timeout SMTP | `SMTP_TIMEOUT=15s` → `aiosmtplib.SMTPTimeoutError` capturada pelo wrapper |
| SMTP 550 (email rejeitado pelo servidor) | `aiosmtplib.SMTPRecipientsRefused` capturada; logada como falha |
| Template faltando | Fail-fast no startup (crash do lifespan — `TemplateNotFound` na primeira chamada) |
| Commit do register falha | Rollback acontece antes do create_task; nenhum email é disparado |
| MailHog vazando pra prod | Validator warn se `SMTP_HOST ∈ {"mailhog","localhost"}`; prod compose não inclui o serviço |
| Flood de create_task | Rate limits capam produção (~8 tasks/min/user worst case) |
| Multiple resends | Cada um cria token novo (random); todos expiram em 24h; verify usa `getdel` → só um funciona |
| User deleta conta durante flight do email | Email chega, link clicado: `verify_email` busca user em `_get_user_by_id` com `deleted_at is NULL` → retorna `InvalidVerificationTokenError` |
| User muda email (não implementado ainda) | N/A — feature futura precisará criar novo token |
| Nome com caracteres Unicode raros no template | `autoescape` + charset utf-8 no MIME cobrem |
| Muito grande: nome de 120 chars + link de ~140 chars | Template comporta; nenhum limite de largura quebrado |
| FRONTEND_URL com trailing slash | `.rstrip('/')` no wrapper normaliza |
| FRONTEND_URL com http em prod | Warning em `validate_settings_for_production` |
| Atacante injeta CRLF no nome via sign-up direto no DB | Jinja autoescape torna visíveis como texto; MIME headers (`To`, `Subject`) não recebem `name`, só `{{ name }}` no body |
| SMTP cai por 1h | Todos os emails desse período perdidos; usuários usam `/resend-verification` quando voltar |
| Processo reinicia com task pendente | Task perdida (é só memória); usuário usa resend |

## 9. Testing / verificação manual

Projeto não tem suite de testes. Validação via MailHog UI:

| # | Passo | Resultado esperado |
|---|---|---|
| 1 | `docker compose up --build` | api, postgres, redis, minio, mailhog healthy |
| 2 | `curl -X POST :8000/auth/register -H 'Content-Type: application/json' -d '{"name":"João Silva","email":"joao@test.com","password":"SenhaForte@2026","date_of_birth":"1990-01-01"}'` | 200 `{"message":"Se este email..."}` em <200ms |
| 3 | Abrir `http://localhost:8025` | Email de `noreply@localhost` para `joao@test.com`, subject "Confirme seu email" |
| 4 | Ver HTML do email no MailHog | Botão azul, fallback URL clicável, nome "João Silva" |
| 5 | Copiar token do link e `curl -X POST :8000/auth/verify-email -d '{"token":"..."}'` | 200 `{"message":"Email verificado..."}` |
| 6 | Tentar verify-email com mesmo token de novo | 400 `{"error":{"code":"INVALID_VERIFICATION_TOKEN",...}}` (getdel atômico) |
| 7 | `curl -X POST :8000/auth/resend-verification -d '{"email":"joao@test.com"}'` | 200 mensagem neutra; logs mostram "já verificado" |
| 8 | `curl -X POST :8000/auth/resend-verification -d '{"email":"nao-existe@test.com"}'` | 200 mesma mensagem neutra; logs "email inexistente" |
| 9 | Criar novo user sem verificar, chamar resend | 200 + novo email no MailHog |
| 10 | Chamar resend 2x em <10min | 1ª: 200, 2ª: 429 `{"error":{"code":"RATE_LIMITED",...}}` |
| 11 | Parar mailhog, registrar novo user | Register retorna 200 normalmente; log `WARNING Failed to send verification email` |
| 12 | Registrar user com nome `<script>alert(1)</script> Silva` | Email no MailHog mostra texto literal `<script>...</script>` (escaped) |

## 10. Arquivos afetados

**Novos (4):**
- `app/core/email.py`
- `app/core/templates/emails/verification.html`
- `app/core/templates/emails/verification.txt`
- `docs/superpowers/specs/2026-04-16-email-verification-design.md` (este arquivo)

**Modificados (8):**
- `pyproject.toml`
- `app/core/config.py`
- `app/features/auth/schemas.py`
- `app/features/auth/service.py`
- `app/features/auth/router.py`
- `app/features/auth/rate_limit.py`
- `docker-compose.yml`
- `.env.example`

## 11. Observabilidade & logs

Formato padronizado em `logger.info` e `logger.warning` com campos estruturados (key=value) para parseabilidade em SIEM.

| Evento | Level | Módulo | Exemplo de mensagem |
|---|---|---|---|
| Verification email enviado com sucesso | INFO | `core.email` | `Verification email sent (hash=a1b2c3d4e5f6g7h8)` |
| Verification email falhou | WARNING | `core.email` | `Failed to send verification email (hash=a1b2c3d4e5f6g7h8)` + traceback |
| Resend: email inexistente | INFO | `features.auth.service` | `Resend: email inexistente (hash=a1b2c3d4e5f6g7h8)` |
| Resend: email já verificado | INFO | `features.auth.service` | `Resend: email já verificado (hash=a1b2c3d4e5f6g7h8)` |
| SMTP connection error | WARNING | `core.email` | incluído via `exc_info=True` |
| Rate limit hit em resend | (implícito pelo `check_rate_limit` existente — 429 logado pelo handler global) | | |

**Métricas (fora de escopo):** contador de `emails_sent_total`, `emails_failed_total`, `smtp_latency_seconds`. Adicionável depois com Prometheus exporter sem alterar contratos existentes.

## 12. Performance

| Aspecto | Decisão | Trade-off |
|---|---|---|
| SMTP connection pooling | Sem pool — nova conexão por email | Latência +100-300ms/email. Simples. Volume esperado <100/h torna pool irrelevante. Pool fica para quando houver métrica de contenção |
| Jinja2 auto_reload | Ligado em dev, desligado em prod | Dev: mudanças de template refletem sem restart (~5ms overhead). Prod: templates em memória, render ~sub-ms |
| Template caching | Default do Jinja (compiled templates em memória, indefinido) | Sem preocupação — 2 templates pequenos |
| create_task overhead | ~microsegundos | Negligível |
| MIME rendering | `EmailMessage` stdlib + `add_alternative` | Implementação C otimizada do stdlib |
| Concurrent emails | Limitado pelo event loop + rate limits | Workers do Uvicorn (4 em prod) × ~10 emails em voo simultâneos por worker = 40 capacity teórica |

Benchmarks não executados neste ciclo — ficam para quando houver métrica real em produção apontando gargalo.

## 13. Dependências — revisão de segurança

| Dep | Versão pinned | CVEs conhecidos (abril/2026) | Manutenção |
|---|---|---|---|
| `aiosmtplib` | `>=3.0.2,<4.0.0` | Nenhum CVE crítico na série 3.x | Ativo, cobrado pela equipe ajax/pypa |
| `jinja2` | `>=3.1.4,<4.0.0` | CVE-2024-22195 (sandbox escape em `xmlattr`, não afetável — não usamos sandbox mode) e CVE-2024-56201 (ainda no xmlattr filter, mitigado na 3.1.5) | Ativo via Pallets |

**Políticas usadas:**
- `autoescape=select_autoescape(["html"])` — única configuração que prevém XSS via templates HTML
- Sandbox mode **não** habilitado (templates são trust boundary: vêm do repo, não de user input)
- `aiosmtplib` valida cert TLS do servidor SMTP por padrão (via `ssl.create_default_context()`)

Ambas as deps são mantidas ativamente, com releases recentes e bom histórico de response a CVEs.

## 14. Plano de rollback

Feature é aditiva — não remove comportamento existente. Rollback tem 3 níveis:

**Nível 1 — Rollback de código (full revert):**
```bash
git revert <commit>
docker compose up --build
```

**Nível 2 — Desabilitar envio sem revert:**
- Setar `SMTP_HOST=invalid-host-to-break-email` no `.env`
- Reiniciar api
- Todos os sends falham no lookup DNS; logados como falha, usuários usam resend quando corrigido
- Register e verify-email continuam funcionando

**Nível 3 — Desabilitar task sem alterar SMTP:**
- Comentar a linha `asyncio.create_task(...)` em `register_user` e `resend_verification_email`
- Reiniciar api
- Register funciona; nenhum email é enviado
- Endpoint `/auth/resend-verification` fica no-op (sempre retorna 200 neutra)

**Sem migration DB:** nada a reverter no schema. `email_verify:*` no Redis são ephemeral (24h TTL) e se auto-limpam.

## 15. Questões em aberto

Decisões que podem precisar ser revisitadas após feedback de uso real:

1. **Tamanho do `RESEND_EMAIL` window** (1 em 10min): talvez restritivo demais pra casos legítimos (email foi pra spam, usuário viu 5min depois, quer reenviar). Pode relaxar pra `(2, 600)`.
2. **SMTPS (porta 465)**: alguns provedores legados / corporativos só oferecem SMTPS. Se adoção reclamar, adicionar `SMTP_SSL` setting.
3. **Retry automático**: cada email perdido hoje vira UX ruim (usuário tem que clicar "reenviar"). Se métricas mostrarem muita perda por timeouts transitórios, migrar para fila Redis + worker (descrita como Opção C no brainstorming).
4. **Multi-idioma**: atualmente template hardcoded em pt-BR. Se o projeto crescer pra internacional, usar `Accept-Language` do request ou coluna `locale` no User.
5. **Rastreamento de entrega**: integração com webhook do provedor (SES SNS, Postmark webhook, etc.) para detectar bounces/complaints. Fora de escopo mas arquitetura permite.

## 16. Fora de escopo (explicitamente)

- Envio de email para password reset (futuro)
- Queue-based delivery com retry exponencial (YAGNI — `create_task` cobre o caso hoje)
- DKIM / SPF / DMARC (responsabilidade do operador do SMTP, não do código)
- Templates WYSIWYG / CMS (overkill)
- Métricas de delivery rate (adicionável depois sem quebrar contrato)
- Webhook bounce/complaint handling
- Multi-idioma
- SMTPS (porta 465) — só STARTTLS (587) neste ciclo
- HttpUrl validation no `FRONTEND_URL` — string simples por enquanto
- Compressão de imagens / assets embebidos em emails — sem imagens atualmente
