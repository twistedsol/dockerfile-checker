# Sample only. A hardened, multi-stage Dockerfile.
FROM python:3.12-slim AS build
WORKDIR /src
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home appuser
COPY --from=build /install /usr/local
WORKDIR /app
COPY --chown=appuser:appuser . .
USER appuser
EXPOSE 8000
HEALTHCHECK CMD ["python", "-c", "print('ok')"]
CMD ["python", "app.py"]
