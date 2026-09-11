FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/freelocker-server ./cmd/server && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/freelocker-server /freelocker-server
COPY --from=build --chown=65532:65532 /out/data /data
ENV FREELOCKER_MASTER_SECRET_FILE=/data/master.key
VOLUME /data
EXPOSE 8080 8443
ENTRYPOINT ["/freelocker-server"]
CMD ["serve"]
