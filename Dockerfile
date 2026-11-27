# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0-dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/caplock/caplock/internal/version.Version=${VERSION}" \
    -o /out/caplock ./cmd/caplock

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/caplock /usr/local/bin/caplock
ENTRYPOINT ["/usr/local/bin/caplock"]
