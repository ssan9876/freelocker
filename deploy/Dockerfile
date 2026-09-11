# Stage 1: build the React console into internal/server/webui/dist.
FROM node:22 AS web
WORKDIR /src
COPY web web
RUN cd web && npm ci && npm run build

# Stage 2: build the server with the console embedded.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/internal/server/webui/dist ./internal/server/webui/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/freelocker-server ./cmd/server && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/freelocker-server /freelocker-server
COPY --from=build --chown=65532:65532 /out/data /data
ENV FREELOCKER_MASTER_SECRET_FILE=/data/master.key
ENV FREELOCKER_RELEASE_DIR=/data/releases
VOLUME /data
EXPOSE 8080 8443
ENTRYPOINT ["/freelocker-server"]
CMD ["serve"]
