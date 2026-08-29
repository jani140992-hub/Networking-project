# Multi-stage production container for NetSphere Platform
FROM python:3.12-slim AS builder

WORKDIR /app
COPY pyproject.toml setup.py README.md ./
COPY netsphere/ netsphere/
COPY docs/ docs/
COPY tests/ tests/
COPY scripts/ scripts/

RUN pip install --no-cache-dir build && python -m build

FROM python:3.12-slim AS runtime

LABEL maintainer="NetSphere Authors <jani140992-hub@users.noreply.github.com>"
LABEL description="NetSphere Enterprise Network Operations, Protocol Engineering & Telemetry Platform"

WORKDIR /app
COPY --from=builder /app /app

EXPOSE 8080 8081

ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=8080

ENTRYPOINT ["python", "main.py"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
