FROM ghcr.io/home-assistant/base-python:3.14-alpine3.24

ENV LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt

# Install Python deps. Most have prebuilt wheels on Alpine / Python 3.12
# (cryptography, aiohttp, pydantic-core). Keep build deps available only
# if a wheel is missing; pip will fall through to source build.
COPY rootfs/opt/access_control/requirements.txt /tmp/requirements.txt
# Build-deps are installed in a virtual package and purged in the same layer
# so they never reach the final image. hadolint DL3018 (pin versions) is
# muted because these are ephemeral and tracked by the base-image's Alpine
# version pin in the multi-architecture base image above.
# hadolint ignore=DL3018
RUN apk add --no-cache --virtual .build-deps \
        gcc musl-dev libffi-dev openssl-dev \
    && pip3 install --no-cache-dir -r /tmp/requirements.txt \
    && apk del --no-network .build-deps \
    && rm -f /tmp/requirements.txt

# Copy add-on rootfs (entrypoint, app source, etc.)
COPY rootfs /
RUN chmod a+x /run.sh

# OCI labels (populated by home-assistant/builder action)
ARG BUILD_ARCH
ARG BUILD_DATE
ARG BUILD_DESCRIPTION
ARG BUILD_NAME
ARG BUILD_REF
ARG BUILD_REPOSITORY
ARG BUILD_VERSION

LABEL \
    io.hass.name="${BUILD_NAME}" \
    io.hass.description="${BUILD_DESCRIPTION}" \
    io.hass.url="https://github.com/nstefanelli/hassio-access-control" \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.type="app" \
    io.hass.version="${BUILD_VERSION}" \
    maintainer="Nick Stefanelli" \
    org.opencontainers.image.title="${BUILD_NAME}" \
    org.opencontainers.image.description="${BUILD_DESCRIPTION}" \
    org.opencontainers.image.source="https://github.com/${BUILD_REPOSITORY}" \
    org.opencontainers.image.revision="${BUILD_REF}" \
    org.opencontainers.image.version="${BUILD_VERSION}" \
    org.opencontainers.image.created="${BUILD_DATE}" \
    org.opencontainers.image.licenses="MIT"

CMD ["/run.sh"]
