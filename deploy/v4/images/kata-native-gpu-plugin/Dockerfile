# Kata-native CDI GPU device plugin (наш реестр-совместимый вариант сборки).
# База golang -> сборка; финальный слой debian:bookworm-slim (в зеркале Harbor proxy),
# чтобы не зависеть от gcr.io/distroless.
FROM harbor.platform.rtx.local/proxy-dockerhub/library/golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod tidy || true
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /out/nvidia-cdi-device-plugin ./main.go && ls -l /out
FROM harbor.platform.rtx.local/proxy-dockerhub/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/nvidia-cdi-device-plugin /usr/bin/nvidia-cdi-device-plugin
ENTRYPOINT ["/usr/bin/nvidia-cdi-device-plugin"]
