FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    libexif-dev libjpeg-dev libpng-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/

RUN useradd -m -u 1000 appuser
RUN mkdir -p /photos /app/data && chown -R appuser:appuser /photos /app/data

USER appuser

EXPOSE 5000

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV DB_PATH=/app/data/phototagger.db

CMD ["python3", "app.py"]
