# CLI in a container (e.g. for CI pipelines):
#   docker build -t samlscope . && docker run --rm -i samlscope --json < message.b64
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir . && useradd -r -u 10001 scope
USER 10001
ENTRYPOINT ["samlscope"]
