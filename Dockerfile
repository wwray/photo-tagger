FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    libexif-dev libjpeg-dev libpng-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/

RUN mkdir -p /photos /app/data

EXPOSE 5000

ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV DB_PATH=/app/data/phototagger.db

# Baked in by docker-publish.yml (--build-arg GIT_SHA=<commit>) so the app
# can show which build is actually running (header version badge) — the
# whole reason this exists is "did my rebuild actually pick up the fix,
# or am I still looking at the old image?" being otherwise unanswerable
# from the UI alone. Defaults to "dev" so a plain local `docker build`
# with no build-arg still works.
ARG GIT_SHA=dev
ENV GIT_SHA=${GIT_SHA}

# Deliberately stays root here: app.py drops privileges to PUID/PGID itself
# right after start (see the os.setuid() call near the top of app.py). A
# fixed `USER appuser` here would make PUID/PGID silently do nothing, since
# a non-root process can't setuid to an arbitrary other user.
CMD ["python3", "app.py"]
