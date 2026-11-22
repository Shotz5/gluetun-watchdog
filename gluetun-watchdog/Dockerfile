FROM python:3.15-alpine

RUN pip install --no-cache-dir --root-user-action=ignore docker requests cryptography

WORKDIR /app
COPY watchdog.py wireguard.py ca.rsa.4096.crt ./

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/app/watchdog.py"]
