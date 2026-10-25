FROM python:3.12-slim

# Install Chromium for headless PDF report generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

ENV PORT=8080
ENV HOST=0.0.0.0

EXPOSE 8080

CMD ["python3", "server.py"]
