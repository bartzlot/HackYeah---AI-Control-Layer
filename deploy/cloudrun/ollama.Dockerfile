# Ollama sidecar for Cloud Run with the judge / local model baked into the image (no pull at start).
FROM ollama/ollama:latest
ARG MODEL=qwen3.5:0.8b
ENV OLLAMA_HOST=127.0.0.1:11434
RUN ollama serve & pid=$!; \
    for i in $(seq 1 60); do ollama list >/dev/null 2>&1 && break; sleep 1; done; \
    ollama pull "$MODEL" && kill $pid
