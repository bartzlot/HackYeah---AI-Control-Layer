# syntax=docker/dockerfile:1
# One image for the gateway (default CMD) and cloud-sim (compose sets `python -m cloud_sim`).
# Build context = repo root: docker build -f w1-gateway/Dockerfile .

FROM python:3.13-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.5 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
# third-party deps first: this layer is rebuilt only when the lock or a manifest changes
COPY pyproject.toml uv.lock ./
COPY contracts/pyproject.toml contracts/
COPY w2-core/pyproject.toml w2-core/
COPY w1-gateway/pyproject.toml w1-gateway/
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-install-workspace
# workspace packages, installed non-editable so the runtime image needs no /src
COPY contracts contracts
COPY w2-core w2-core
COPY w1-gateway w1-gateway
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim
RUN useradd --create-home --uid 10001 aicl && mkdir -p /app/data && chown aicl /app/data
COPY --from=build /app/.venv /app/.venv
COPY policy /app/policy
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1 \
    AICL_POLICY=/app/policy/policy.yaml AICL_DATA_DIR=/app/data \
    AICL_AUDIT_PATH=/app/data/audit.jsonl AICL_BUDGET_DB=/app/data/budget.db \
    AICL_CLOUDSIM_HOST=0.0.0.0
WORKDIR /app
USER aicl
EXPOSE 18080 18200
# until the gateway has a policy-driven entrypoint (T-901) this serves create_app() defaults
CMD ["uvicorn", "--factory", "aicl_gateway.app:create_app", "--host", "0.0.0.0", "--port", "18080"]
