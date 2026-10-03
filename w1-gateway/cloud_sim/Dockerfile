FROM python:3.13-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn pyyaml
COPY w1-gateway/cloud_sim /app/cloud_sim
EXPOSE 18200
CMD ["python", "-m", "cloud_sim"]
