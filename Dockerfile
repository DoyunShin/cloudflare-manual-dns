# --- Frontend build stage: compile the React SPA to static assets ---------
FROM node:22-slim AS frontend

WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build

# --- Application stage -----------------------------------------------------
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src/ ./src/
RUN uv sync --frozen --no-dev

COPY docker/ ./docker/
RUN chmod +x docker/entrypoint.sh

# Built SPA served by FastAPI (located via FRONTEND_DIST).
COPY --from=frontend /fe/dist /app/frontend_dist
ENV FRONTEND_DIST=/app/frontend_dist

RUN groupadd --system cfproxy && useradd --system --gid cfproxy --no-create-home cfproxy
USER cfproxy

ENV PATH="/app/.venv/bin:${PATH}"

EXPOSE 8080

ENTRYPOINT ["docker/entrypoint.sh"]
