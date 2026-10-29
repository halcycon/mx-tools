# mx agent: probe backend for the D.A.R.T. health check / full report.
# Published as ghcr.io/halcycon/mx-tools-agent by .github/workflows/agent-image.yml.
# Deploy with deploy/agent/compose.yaml.

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/mx .

# Static, non-root, with CA certificates (needed to validate mail-server certificates).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mx /usr/local/bin/mx
USER nonroot:nonroot
EXPOSE 8788
ENTRYPOINT ["/usr/local/bin/mx"]
CMD ["agent", "--listen", "0.0.0.0:8788", "--allow-lan"]
