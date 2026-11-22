FROM python:3.15-alpine

RUN pip install --no-cache-dir --root-user-action=ignore docker requests

WORKDIR /app
COPY watchdog.py .

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/app/watchdog.py"]
