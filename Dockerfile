# DRAGNET - slim, non-root image. Runtime is stdlib-only; the API and signing extras are included.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY dragnet ./dragnet
RUN pip wheel --no-cache-dir --wheel-dir /wheels ".[api,sign]"

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DRAGNET_DATA=/data
RUN useradd --create-home --uid 10001 dragnet && mkdir /data && chown dragnet /data
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
WORKDIR /app
COPY --chown=dragnet fixtures ./fixtures
USER dragnet
LABEL org.opencontainers.image.source="https://github.com/rakshit-737/dragnet" \
      org.opencontainers.image.description="Evidence-to-actor attribution with ACH and false-flag reasoning" \
      org.opencontainers.image.licenses="MIT"
ENTRYPOINT ["dragnet"]
CMD ["demo"]
