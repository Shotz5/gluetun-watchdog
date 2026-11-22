FROM python:3.15-alpine

RUN pip install --no-cache-dir --root-user-action=ignore docker requests

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "watchdog.py"]
