# DRAGNET - slim, non-root image. Runtime is stdlib-only; the API and signing extras are included.
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY dragnet ./dragnet
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[api,sign]"

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DRAGNET_DATA=/data
RUN useradd --create-home --uid 10001 dragnet && mkdir /data && chown dragnet /data
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
WORKDIR /app
USER dragnet
LABEL org.opencontainers.image.source="https://github.com/rakshit-737/dragnet-actor-attribution" \
      org.opencontainers.image.description="Evidence-to-actor attribution with ACH and false-flag reasoning" \
      org.opencontainers.image.licenses="MIT"
ENTRYPOINT ["dragnet"]
CMD ["demo"]
