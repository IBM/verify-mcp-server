FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir -e .

RUN mkdir -p /data /certs

EXPOSE 8004

ENTRYPOINT ["python", "-m", "src"]
