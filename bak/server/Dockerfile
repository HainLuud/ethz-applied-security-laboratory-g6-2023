# syntax=docker/dockerfile:1

FROM restic/rest-server:latest

ENV DATA_DIRECTORY=/app/data

ENV PASSWORD_FILE=${DATA_DIRECTORY}/.htpasswd

WORKDIR /app

# Create a non-privileged user that the app will run under.
# See https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

# Create the volume mountpoint.
RUN mkdir ${DATA_DIRECTORY} \
    && chown appuser:appuser ${DATA_DIRECTORY}

# Mount the volume.
VOLUME ${DATA_DIRECTORY}

# Switch to the non-privileged user to run the application.
USER appuser
