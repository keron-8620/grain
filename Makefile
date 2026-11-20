.PHONY: build test verify coverage clean docker-build docker-push run dev-key dist help version swag

# ===== 项目配置：版本默认来自 Git，发布时可通过 VERSION=x.y.z 覆盖 =====
BINARY_NAME=grain
# VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
VERSION=0.1
COMMIT_ID?=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME?=$(shell date +"%Y-%m-%d %H:%M:%S")
DOCKER_IMAGE?=swr.cn-north-4.myhuaweicloud.com/danqingzhao/grain
DOCKER_TAG?=$(VERSION)

export GOTMPDIR := $(HOME)/.temp

# ===== Go 工具链：从 go.mod 动态读取，升级 go.mod 后自动适配 =====
# 优先读取 toolchain 指令，否则回退到 go 指令；都失败时用 go env GOVERSION。
GO_VERSION := $(shell awk '/^toolchain[[:space:]]/ { sub(/^go/, "", $$2); print $$2; exit } /^go[[:space:]]/ { v=$$2 } END { if (!v) exit; if (!f) print v }' go.mod 2>/dev/null)
ifeq ($(GO_VERSION),)
GO_VERSION := $(shell go env GOVERSION | sed 's/^go//')
endif
# GOTOOLCHAIN 需要完整补丁版本号（go1.27.x），这里自动把 "1.27" 补成 "1.27.0"。
GO_VERSION := $(shell echo "$(GO_VERSION)" | awk -F. 'NF==2 {print $$0".0"; next} NF>=3 {print $$1"."$$2"."$$3; next} {print}')

# host 平台：检查工具运行在当前主机上，不应被交叉编译目标影响。
HOST_GOOS   := $(shell go env GOHOSTOS)
HOST_GOARCH := $(shell go env GOHOSTARCH)

# 统一的工具链环境：强制使用项目声明的 Go 版本 + host 平台。
TOOL_ENV := GOTOOLCHAIN=go$(GO_VERSION) GOOS=$(HOST_GOOS) GOARCH=$(HOST_GOARCH)

# ===== 检查工具版本（升级 Go 大版本时按需同步升级；CI 可用环境变量覆盖）=====
# 说明：
#   - golangci-lint：Go 1.27 需要 v2.13.0+，推荐 v2.14.0+
#   - gosec        ：Go 1.27 的导出数据版本 5 需要 v2.30.0+
#   - govulncheck  ：v1.9.0+ 已支持 Go 1.27
#   - swag         ：与 go.mod 中的 swaggo/swag 依赖版本保持一致
GOLANGCI_LINT_VERSION ?= v2.14.0
GOSEC_VERSION        ?= v2.30.0
GOVULNCHECK_VERSION  ?= v1.9.0
SWAG_VERSION         ?= v1.16.6

# 全部通过 go run + 项目工具链运行，避免 PATH 中预编译二进制的版本错位。
GOLANGCI_LINT = $(TOOL_ENV) go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOSEC         = $(TOOL_ENV) go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
GOVULNCHECK   = $(TOOL_ENV) go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
SWAG          = $(TOOL_ENV) go run github.com/swaggo/swag/cmd/swag@$(SWAG_VERSION)

# ===== 交叉编译目标（仅 build 使用；verify 通过 TOOL_ENV 强制 host 平台）=====
export GOOS ?= linux
export GOARCH ?= amd64

# go 工具链临时目录指向用户缓存目录，避免 /tmp 空间不足导致竞态测试链接失败
# GOTMPDIR ?= $(HOME)/.cache/go-tmp
# export GOTMPDIR

help:  ## 显示帮助信息
	@echo "可用的命令:"
	@echo ""
	@grep -E '^[a-zA-Z_0-9%-]+:.*?## .*$$' $(word 1,$(MAKEFILE_LIST)) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build:  ## 构建二进制文件
	@echo "构建项目..."
	@CGO_ENABLED=0 go build \
		-trimpath \
		-ldflags "-s -w \
			-X 'main.version=$(VERSION)' \
			-X 'main.commitID=$(COMMIT_ID)' \
			-X 'main.buildTime=$(BUILD_TIME)' \
			-X 'main.goVersion=$(shell go version)' \
			-X 'main.goOS=$(shell go env GOOS)' \
			-X 'main.goArch=$(shell go env GOARCH)'" \
		-o bin/$(BINARY_NAME) main.go
	@echo "构建完成: bin/$(BINARY_NAME)"

swag:  ## 生成swagger文档
	@echo "开始生成swagger文档..."
	@$(SWAG) init
	@echo "生成swagger文档完成"

verify:  ## 执行格式、静态检查、竞争检测和安全扫描
	@echo "===== go vet 静态检查 ====="
	@$(TOOL_ENV) go vet ./...

	@echo "===== golangci-lint 代码规范 ====="
	@$(GOLANGCI_LINT) run --timeout 5m

	@echo "===== gosec 安全漏洞扫描 ====="
	@$(GOSEC) -quiet --exclude-dir=.venv ./...

	@echo "===== govulncheck 依赖漏洞 ====="
	@$(GOVULNCHECK) ./...

	@echo "===== go test 单元测试（含竞争检测） ====="
	@$(TOOL_ENV) CGO_ENABLED=1 go test -race -timeout 600s -parallel $(shell nproc) -coverprofile=coverage.out -failfast ./...

coverage:  ## 生成覆盖率报告
	@mkdir -p html
	@$(TOOL_ENV) go test -coverprofile=coverage.out ./...
	@$(TOOL_ENV) go tool cover -html=coverage.out -o html/coverage.html
	@$(TOOL_ENV) go tool cover -func=coverage.out | tail -1

clean:  ## 清理构建产物
	@echo "清理构建产物..."
	@if [ -f "bin/$(BINARY_NAME)" ]; then \
		rm -f bin/$(BINARY_NAME); \
		echo "已删除 bin/$(BINARY_NAME)"; \
	fi
	@for f in artweb-*.tar.gz; do \
		if [ -f "$$f" ]; then \
			rm -f "$$f"; \
			echo "已删除 $$f"; \
		fi \
	done
	@echo "清理完成"

docker-build:  ## 构建 Docker 镜像
	@echo "构建 Docker 镜像: $(DOCKER_IMAGE):$(DOCKER_TAG)"
	@podman build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "Docker 镜像构建完成"

docker-push:  ## 推送 Docker 镜像
	@echo "推送 Docker 镜像: $(DOCKER_IMAGE):$(DOCKER_TAG)"
	@podman push $(DOCKER_IMAGE):$(DOCKER_TAG)
	@echo "Docker 镜像推送完成"

# 仅用于本地开发的 JWT 私钥。文件被 .gitignore 忽略，不得提交或打包。
DEV_KEY_FILE ?= config/dev-signing-key.pem
DEV_KEY_BITS ?= 3072

dev-key:  ## 生成本地开发 JWT 私钥（config/dev-signing-key.pem，不入库）
	@if [ -f "$(DEV_KEY_FILE)" ]; then \
		echo "已存在 $(DEV_KEY_FILE)，未覆盖；如需轮换请先删除该文件"; \
	else \
		mkdir -p "$(dir $(DEV_KEY_FILE))"; \
		openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$(DEV_KEY_BITS) -out "$(DEV_KEY_FILE)"; \
		chmod 600 "$(DEV_KEY_FILE)"; \
		echo "已生成 $(DEV_KEY_FILE)（$(DEV_KEY_BITS) bits，权限 600）"; \
	fi

run:  ## 运行应用
	@echo "运行应用..."
	@$(TOOL_ENV) go run main.go

dist: build  ## 打包发布包 (tar.gz)：自动排除私钥、.env、数据库等敏感文件
	@echo "为 resource/*/script/ 添加可执行权限..."
	@find resource -path '*/script/*' -type f -exec chmod +x {} + 2>/dev/null || true
	@echo "检查仓库是否仍跟踪敏感文件..."
	@if git ls-files '*.pem' '*.key' '*.crt' '*.p12' '*.pfx' '*.db' '.env' '.env.*' | grep -q .; then \
		echo "拒绝打包：仓库仍在跟踪敏感文件，请先从索引移除："; \
		git ls-files '*.pem' '*.key' '*.crt' '*.p12' '*.pfx' '*.db' '.env' '.env.*'; \
		exit 1; \
	fi
	@echo "打包为 artweb-$(VERSION).tar.gz ..."
	@rm -rf /tmp/artweb-dist && mkdir -p /tmp/artweb-dist/artweb-$(VERSION)
	@for item in config bin .env cmd sql resource html README.md; do \
		if [ -e "$$item" ]; then \
			cp -r "$$item" /tmp/artweb-dist/artweb-$(VERSION)/; \
		fi \
	done
	@find /tmp/artweb-dist -type f \( \
		-name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.p12' -o -name '*.pfx' \
		-o -name '*.db' -o -name '*.sqlite' -o -name '.env' -o -name '.env.*' -o -name 'coverage.html' \
	\) -delete
	@find /tmp/artweb-dist -type d \( -name '.git' -o -name 'logs' \) -prune -exec rm -rf {} + 2>/dev/null || true
	@tar -czf artweb-$(VERSION).tar.gz -C /tmp/artweb-dist artweb-$(VERSION)
	@if tar -tzf artweb-$(VERSION).tar.gz | grep -Eq '(\.pem|\.key|\.crt|\.p12|\.pfx|\.db|\.sqlite)$$|(^|/)\.env(\.|$$)|/coverage\.html$$'; then \
		echo "发布包包含敏感文件，已删除产物并中止"; \
		rm -f artweb-$(VERSION).tar.gz; \
		exit 1; \
	fi
	@rm -rf /tmp/artweb-dist
	@echo "打包成功: artweb-$(VERSION).tar.gz ($$(du -h artweb-$(VERSION).tar.gz | awk '{print $$1}'))"

version:  ## 显示版本信息
	@go run main.go -v