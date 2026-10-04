# A developer laptop in miniature: Claude Code + git + curl, trusting the AICL root CA, DNS from the network.
# Nothing in here knows about AICL except the trusted CA (installed at start from the gateway's volume).
FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g @anthropic-ai/claude-code && npm cache clean --force
COPY entrypoint.sh /usr/local/bin/devbox-entrypoint
RUN chmod +x /usr/local/bin/devbox-entrypoint && mkdir -p /work && chown node /work
WORKDIR /work
ENTRYPOINT ["devbox-entrypoint"]
