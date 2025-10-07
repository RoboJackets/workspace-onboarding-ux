# syntax = docker/dockerfile:1.19

FROM node:22.20.0 AS frontend

RUN npm install -g npm@latest

COPY --link package.json package-lock.json elm.json /app/
COPY --link elm/ /app/elm/
COPY --link js/ /app/js/
COPY --link static/ /app/static/

WORKDIR /app/

RUN set -eux && \
    npm ci --no-progress && \
    npm run build

FROM python:3.14-slim-trixie

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="${PATH}:/root/.local/bin" \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1

RUN set -eux && \
    apt-get update && \
    apt-get upgrade -qq --assume-yes && \
    apt-get install -qq --assume-yes build-essential python-dev libpcre3 libpcre3-dev zopfli && \
    python3 -m pip install --upgrade pip && \
    python3 -m pip install poetry && \
    useradd --home-dir /app/ --create-home --shell /bin/bash uwsgi

WORKDIR /app/

COPY --chown=uwsgi:uwsgi --from=frontend /app/static/ /app/static/

COPY --chown=uwsgi:uwsgi /templates/ /app/templates/

COPY --chown=uwsgi:uwsgi /workspace_onboarding_ux.py /pyproject.toml /poetry.lock /app/

RUN set -eux && \
    POETRY_VIRTUALENVS_CREATE=false poetry install --only main --no-root --no-interaction --no-ansi && \
    zopfli --gzip -v --i10 /app/static/app.js && \
    touch /app/static/app.js.gz /app/static/app.js && \
    sed -i 's/return self.request.get_json()/        return self.request.get_json(silent=True)/g' /usr/local/lib/python3.14/site-packages/sentry_sdk/integrations/flask.py

USER uwsgi
