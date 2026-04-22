import re
import unicodedata
from datetime import UTC, date, datetime

from email_validator import EmailNotValidError
from email_validator import validate_email as _validate_email

# ---------------------------------------------------------------------------
# Name
# ---------------------------------------------------------------------------

_PT_LOWERCASE = frozenset({"de", "da", "do", "dos", "das", "e"})
_MULTI_SPACE = re.compile(r"\s{2,}")
_NAME_MAX = 120


def _capitalize_word(word: str) -> str:
    if "-" in word:
        return "-".join(_capitalize_word(p) for p in word.split("-"))
    if "'" in word:
        parts = word.split("'")
        return "'".join(
            p[0].upper() + p[1:].lower() if p else "" for p in parts
        )
    return word[0].upper() + word[1:].lower() if word else word


def _has_forbidden_chars(text: str) -> bool:
    for ch in text:
        if ch in " -'.":
            continue
        cat = unicodedata.category(ch)
        if not cat.startswith("L"):
            return True
    return False


def validate_and_format_name(raw: str) -> str:
    name = raw.strip()
    name = unicodedata.normalize("NFC", name)
    name = _MULTI_SPACE.sub(" ", name)

    if len(name) < 2:
        raise ValueError("Nome deve ter no mínimo 2 caracteres")
    if len(name) > _NAME_MAX:
        raise ValueError(f"Nome deve ter no máximo {_NAME_MAX} caracteres")

    if _has_forbidden_chars(name):
        raise ValueError("Nome contém caracteres inválidos")

    words = name.split()
    if len(words) < 2:
        raise ValueError("Nome deve ter no mínimo 2 palavras")

    parts: list[str] = []
    for i, word in enumerate(words):
        if i > 0 and word.lower() in _PT_LOWERCASE:
            parts.append(word.lower())
        else:
            parts.append(_capitalize_word(word))

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def validate_and_normalize_email(raw: str) -> str:
    """Normaliza email para lowercase integral — incluindo localpart.

    Trade-off aceito: RFC 5321 declara localpart como case-sensitive e
    domínio como case-insensitive. 99%+ dos provedores (Gmail, Outlook,
    corporate Exchange, etc) normalizam o localpart em delivery, mas
    MTAs RFC-strict podem distinguir User@x.com de user@x.com — pra eles
    essa normalização perde a entrega.

    Por que preservamos lower() integral mesmo assim:
    1. Anti-enumeração: sem essa normalização, um atacante poderia criar
       contas paralelas User@x.com, USER@x.com, user@x.com que tecnicamente
       são diferentes, cada uma passando no /register — drena o bucket
       de rate-limit por email e pode mascarar takeover de conta.
    2. Consistência: os logs/hash_email trabalham com o normalizado; sem
       lower integral, mesmo dono de conta teria múltiplos hashes em
       telemetria.
    3. UX: usuários tipicamente não entendem sensibilidade de case e
       digitam inconsistente entre registro e login.

    O custo (incompatibilidade com <1% dos MTAs RFC-strict) é aceitável
    pelo ganho em anti-enum + operacional."""
    raw = raw.strip()
    try:
        result = _validate_email(raw, check_deliverability=False)
    except EmailNotValidError as e:
        raise ValueError(str(e)) from None
    return result.normalized.lower()


# ---------------------------------------------------------------------------
# Password
# ---------------------------------------------------------------------------

COMMON_PASSWORDS = frozenset({
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321",
    "superman", "1qaz2wsx", "7777777", "121212", "000000",
    "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "charlie", "robert", "thomas",
    "hockey", "ranger", "daniel", "starwars", "112233",
    "george", "computer", "michelle", "jessica", "pepper",
    "zxcvbn", "555555", "11111111", "131313", "freedom",
    "777777", "pass", "maggie", "159753", "aaaaaa",
    "ginger", "princess", "joshua", "cheese", "amanda",
    "summer", "love", "ashley", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321",
    "dallas", "austin", "thunder", "taylor", "matrix",
    "minecraft", "admin", "password1", "password123",
    "welcome", "welcome1", "p@ssw0rd", "passw0rd",
    "qwerty123", "admin123", "letmein1", "abc1234",
    "asdfghjkl", "senha", "senha123", "mudar123",
})


_NORM_RE = re.compile(r"[^a-z0-9]")


def _is_common(password: str) -> bool:
    lower = password.lower()
    return lower in COMMON_PASSWORDS or _NORM_RE.sub("", lower) in COMMON_PASSWORDS


# QWERTY US layout — suficiente pro caso comum. Layouts alternativos (Dvorak,
# ABNT2 ç) não são coberto aqui, mas os walks típicos ("qwerty", "asdf",
# "zxcv", "1234") são no mesmo hardware físico.
_KEYBOARD_ROWS = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
)


def _is_sequential(password: str, min_seq: int = 4) -> bool:
    """True se senha contém sequência ASCII (abcd, 1234, dcba) OU keyboard
    walk horizontal (qwer, asdf, zxcv, poiu)."""
    lower = password.lower()

    # Sequência ASCII / repetição (funciona pra qualquer char, não só teclado)
    for i in range(len(lower) - min_seq + 1):
        diffs = [
            ord(lower[i + j + 1]) - ord(lower[i + j])
            for j in range(min_seq - 1)
        ]
        if all(d == 1 for d in diffs):
            return True
        if all(d == -1 for d in diffs):
            return True
        if all(d == 0 for d in diffs):
            return True

    # Keyboard walks horizontais (qwerty layout)
    for row in _KEYBOARD_ROWS:
        for start in range(len(row) - min_seq + 1):
            segment = row[start:start + min_seq]
            if segment in lower or segment[::-1] in lower:
                return True

    return False


_CONTEXT_SPLIT = re.compile(r"[\s@._\-+]+")


def _is_contextual(password: str, context: list[str]) -> bool:
    """Checa se senha contém partes de context (nome, email).
    Split em whitespace + separadores de email (@ . _ - +) — pega
    local-part do email que whitespace-only split não pegaria."""
    lower = password.lower()
    for ctx in context:
        for part in _CONTEXT_SPLIT.split(ctx.lower()):
            if len(part) >= 3 and part in lower:
                return True
    for word in ("auth", "authentication"):
        if word in lower:
            return True
    return False


_PASSWORD_MAX = 128


def validate_password(password: str, context: list[str] | None = None) -> None:
    if len(password) < 8:
        raise ValueError("Senha deve ter no mínimo 8 caracteres")

    if len(password) > _PASSWORD_MAX:
        raise ValueError(f"Senha deve ter no máximo {_PASSWORD_MAX} caracteres")

    if not any(c.isupper() for c in password):
        raise ValueError("Senha deve ter pelo menos uma letra maiúscula")

    if not any(c.isdigit() for c in password):
        raise ValueError("Senha deve ter pelo menos um número")

    if not any(not c.isalnum() for c in password):
        raise ValueError("Senha deve ter pelo menos um caractere especial")

    if _is_common(password):
        raise ValueError("Senha muito comum")

    if _is_sequential(password):
        raise ValueError("Senha contém sequência repetitiva ou crescente")

    if context and _is_contextual(password, context):
        raise ValueError("Senha não pode conter partes do nome ou email")


# ---------------------------------------------------------------------------
# Date of birth
# ---------------------------------------------------------------------------

_MIN_DOB = date(1900, 1, 1)
_MAX_AGE_YEARS = 130
# COPPA (EUA 13+) / GDPR-K baseline. Países EU podem exigir 14/15/16 —
# adotantes que operem nesses países devem aumentar este valor.
_MIN_AGE_YEARS = 13


def validate_date_of_birth(dob: date) -> None:
    today = datetime.now(UTC).date()

    if dob > today:
        raise ValueError("Data de nascimento não pode ser no futuro")

    if dob < _MIN_DOB:
        raise ValueError("Data de nascimento inválida")

    # Idade em anos civis — subtrai 1 se o aniversário ainda não aconteceu
    # este ano. (today - dob).days / 365.25 tem erro de arredondamento que
    # rejeita aniversariante do dia em anos bissextos (ex: 13 anos pontuais
    # ficam em age=12.999...).
    age = today.year - dob.year - (
        (today.month, today.day) < (dob.month, dob.day)
    )
    if age > _MAX_AGE_YEARS:
        raise ValueError("Data de nascimento inválida")

    if age < _MIN_AGE_YEARS:
        raise ValueError(f"Idade mínima é {_MIN_AGE_YEARS} anos")
