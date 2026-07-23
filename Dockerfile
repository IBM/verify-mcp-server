FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir -e .

RUN mkdir -p /data /certs

# Containers must publish on all interfaces; local default in code is 127.0.0.1
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8004

EXPOSE 8004

ENTRYPOINT ["python", "-m", "src"]
