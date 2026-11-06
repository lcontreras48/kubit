FROM python:3.13-alpine AS build

WORKDIR /build
COPY pyproject.toml ./
COPY src ./src
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.13-alpine

ARG KUBIT_COMMIT=unknown
ARG KUBIT_VERSION=development
LABEL org.opencontainers.image.title="Kubit" \
      org.opencontainers.image.description="Evidence-based Kubernetes compatibility monitor" \
      org.opencontainers.image.source="https://github.com/lcontreras48/kubit" \
      org.opencontainers.image.revision="${KUBIT_COMMIT}" \
      org.opencontainers.image.version="${KUBIT_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN addgroup -S -g 65532 kubit \
 && adduser -S -D -H -u 65532 -G kubit kubit
COPY --from=build /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels kubit \
 && rm -rf /wheels

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["kubit"]

