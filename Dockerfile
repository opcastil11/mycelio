# mycd — Mycelio reference daemon
#
# Multi-stage build keeps the runtime image small. The daemon listens
# on raw TLS-TCP (port 4242 by default). Mount TLS cert + key + root
# Ed25519 seed via volumes; configure via env or CLI flags.

FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY mycelio/ ./mycelio/
COPY mycd/ ./mycd/

# Install into the builder venv, then copy to the runtime stage.
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir ".[server]"


FROM python:3.12-slim AS runtime

# Non-root user — anyio servers don't need root for ports >= 1024.
RUN useradd --create-home --uid 1000 mycelio

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /home/mycelio
USER mycelio

EXPOSE 4242

# Default command — override args via docker run / compose.
# In production: pass --tls-cert, --tls-key, --root-key.
ENTRYPOINT ["mycd"]
CMD ["--host", "0.0.0.0", "--port", "4242"]
