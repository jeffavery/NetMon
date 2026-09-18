FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends arp-scan iputils-ping nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates ./templates
COPY static ./static

RUN mkdir -p /data

EXPOSE 8088

CMD ["gunicorn", "--bind", "0.0.0.0:8088", "--workers", "1", "--threads", "8", "--timeout", "300", "app:app"]
