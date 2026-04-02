FROM golang:1.26.1 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    go build -o /out/mpcinfra ./cmd/mpcinfra

FROM gcr.io/distroless/base-debian12:latest

USER nonroot:nonroot
WORKDIR /app

COPY --from=builder /out/mpcinfra /app/mpcinfra

ENTRYPOINT ["/app/mpcinfra"]
