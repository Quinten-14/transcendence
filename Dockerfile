FROM python:3.10-slim-bullseye

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    libpq-dev \
    pkg-config \
    libcairo2-dev \
    gcc \
    build-essential \
    python3-distutils-extra \
    python3-apt \
    libyaml-dev \
    libsystemd-dev \
    libdbus-1-dev \
    libdbus-glib-1-dev \
    libcups2-dev \
    libgirepository1.0-dev \
    gir1.2-gtk-3.0 \
    && apt-get clean

WORKDIR /app

COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt

EXPOSE 8000

ENV DJANGO_SETTINGS_MODULE=transcendence.settings

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "transcendence.wsgi:application"]
