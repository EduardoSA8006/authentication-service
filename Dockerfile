# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Multi-stage build:
#   builder  → instala Poetry + resolve deps em venv isolado
#   runtime  → imagem final, copia só o venv pronto + código (sem Poetry)
#
# Resultado: imagem ~150MB em vez de ~500MB (sem ferramentas de build,
# sem pip cache, sem toolchain). Superfície de ataque menor; pull mais
# rápido em k8s/ECS; nenhum binário extra no container rodando.
# ---------------------------------------------------------------------------

# Base image pinada por digest pra evitar supply-chain drift. docker-compose.prod.yml
# pina os outros serviços do mesmo jeito. Dependabot (.github/dependabot.yml com
# package-ecosystem: docker) abre PR quando sai versão nova — revisar antes de
# aceitar. Update manual:
#   docker pull python:3.12-slim && \
#   docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim@sha256:520153e2deb359602c9cffd84e491e3431d76e7bf95a3255c9ce9433b76ab99a AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1

# Poetry pinado à mesma versão do CI (.github/workflows/ci.yml) pra evitar
# resolution drift silencioso entre dev/CI/prod. Bumps explícitos via PR.
ARG POETRY_VERSION=2.3.4

WORKDIR /app

RUN pip install --no-cache-dir "poetry==${POETRY_VERSION}"

# Copia só os manifests primeiro — cache de layer de deps sobrevive a mudanças
# de código. `poetry install --only main --no-root`: skip pacote próprio
# (código ainda não copiado) e grupo dev.
COPY pyproject.toml poetry.lock ./
RUN poetry install --only main --no-interaction --no-ansi --no-root


# ---------------------------------------------------------------------------
# Runtime stage — minimal image
# ---------------------------------------------------------------------------
FROM python:3.12-slim@sha256:520153e2deb359602c9cffd84e491e3431d76e7bf95a3255c9ce9433b76ab99a AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# User criado ANTES do COPY — permite usar COPY --chown e evita camada
# extra de `chown -R` que duplicaria todos os arquivos na imagem final
# (cada mudança de metadata cria uma nova camada com cópia integral).
RUN addgroup --system --gid 1001 app && \
    adduser --system --uid 1001 --ingroup app app

# Copia só o venv resolvido (sem Poetry, sem pip cache, sem toolchain).
COPY --from=builder --chown=app:app /app/.venv /app/.venv

# Código da aplicação. .dockerignore já exclui tests/, .git/, .env, etc.
COPY --chown=app:app app ./app
COPY --chown=app:app pyproject.toml poetry.lock ./

USER app

EXPOSE 8000

# uvicorn vem do venv copiado (PATH já aponta pra /app/.venv/bin).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
