# ---------- 构建阶段 ----------
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG GOPROXY=https://proxy.golang.org,direct

ENV GOPROXY=${GOPROXY} CGO_ENABLED=0

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X github.com/zxkbazinga/port-guard/internal/version.Version=${VERSION}" \
    -o /out/port-guard ./cmd/port-guard

# ---------- 运行阶段 ----------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && mkdir -p /data
COPY --from=builder /out/port-guard /usr/local/bin/port-guard

ENV TZ=Asia/Shanghai
EXPOSE 8080/tcp 5140/udp
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/port-guard"]
CMD ["--listen", ":8080", "--data", "/data"]
