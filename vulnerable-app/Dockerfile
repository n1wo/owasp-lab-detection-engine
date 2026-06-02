FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vulnerable_app ./vulnerable_app

ENV FLASK_HOST=0.0.0.0
ENV FLASK_PORT=8080
ENV LAB_MODE=insecure
ENV LAB_LOG_FILE=/app/logs/application.jsonl

EXPOSE 8080

CMD ["python", "-m", "vulnerable_app"]

