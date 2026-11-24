VERSION ?= dev
IMAGE   ?= port-guard:latest
LDFLAGS := -s -w -X github.com/zxkbazinga/port-guard/internal/version.Version=$(VERSION)

.PHONY: build test run docker-build docker-build-arm64 clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/port-guard ./cmd/port-guard

test:
	go test ./...

run:
	go run ./cmd/port-guard --listen :8080 --data ./data

# 宿主机架构镜像
docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

# 爱快 ARM 机型镜像（在 x86 机器上交叉构建）
docker-build-arm64:
	docker buildx build --platform linux/arm64 --build-arg VERSION=$(VERSION) -t $(IMAGE)-arm64 .

# 爱快 x86 机型镜像
docker-build-amd64:
	docker buildx build --platform linux/amd64 --build-arg VERSION=$(VERSION) -t $(IMAGE)-amd64 .

clean:
	rm -rf bin data/*.db data/*.db-*
