FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATA_DIR=/data \
    SMTP_LISTEN_PORT=2525 \
    WEB_PORT=8080

WORKDIR /srv

# Dependencies first (cached layer); only the dependency list is read from pyproject.toml.
COPY pyproject.toml .
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']))" > /tmp/requirements.txt \
 && pip install -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

# Application code only (see .dockerignore: an allowlist).
COPY app ./app

RUN useradd --system --uid 10001 --no-create-home trashmail \
 && mkdir /data && chown trashmail /data
USER trashmail

VOLUME /data
EXPOSE 2525 8080
CMD ["python", "-m", "app.main"]
