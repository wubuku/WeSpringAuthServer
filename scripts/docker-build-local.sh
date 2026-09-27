#!/bin/bash

# WeSpringAuthServer 本地构建（中国大陆网络环境）
# 与 RuiChuangQi-AI/scripts/docker-build-local.sh 一样：从国内镜像站预拉基础镜像，
# 重标记为 Dockerfile 使用的名称，再用原有 Dockerfile 在本机构建，不推送。
# Usage: ./scripts/docker-build-local.sh [--arch amd64|arm64] [--tag TAG] [--no-cache]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE_NAME="${DOCKERHUB_USERNAME:-wubuku}/wespring-auth-server"
MIRROR_BASE_URL="${MIRROR_BASE_URL:-docker.m.daocloud.io}"
APT_MIRROR_URL="${APT_MIRROR_URL:-https://mirrors.aliyun.com/ubuntu}"

print_info() { printf '[INFO] %s\n' "$1"; }
print_warning() { printf '[WARNING] %s\n' "$1"; }
print_error() { printf '[ERROR] %s\n' "$1" >&2; }

show_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

从国内镜像站预拉基础镜像，在本机构建 ${IMAGE_NAME}:latest（不推送）。

Options:
  -a, --arch ARCH    目标架构，amd64 或 arm64（默认 amd64）
  -t, --tag TAG      额外的自定义 tag（默认额外创建 sha-*）
  -n, --no-cache     不使用构建缓存
  -h, --help         显示帮助

Environment:
  DOCKERHUB_USERNAME  镜像名前缀（默认 wubuku，无需登录）
  MIRROR_BASE_URL    基础镜像站（默认 docker.m.daocloud.io）
  APT_MIRROR_URL     Ubuntu 软件源（默认 https://mirrors.aliyun.com/ubuntu）

Example: $0 --arch amd64 --tag v1.0.0
EOF
}

pull_base_images() {
    local arch="$1"
    local image mirrored_image

    # 对应当前 Dockerfile 的两个 FROM；与参考脚本一样，镜像站失败时尝试直连。
    for image in eclipse-temurin:17-jdk-jammy eclipse-temurin:17-jre-jammy; do
        mirrored_image="${MIRROR_BASE_URL}/${image}"
        print_info "拉取基础镜像：${mirrored_image} (linux/${arch})"
        if docker pull --platform "linux/${arch}" "$mirrored_image"; then
            docker tag "$mirrored_image" "$image"
            print_info "已重标记为：${image}"
        else
            print_warning "镜像站拉取失败，尝试直连：${image}"
            docker pull --platform "linux/${arch}" "$image"
        fi
    done
}

prepare_dockerfile() {
    local source_file="$1"
    local output_file="$2"

    # 不修改仓库里的 Dockerfile。通过 BuildKit secret 提供有效的 Maven 国内镜像配置，
    # 覆盖缓存中可能残留的空 settings.xml；同时把 Ubuntu 软件源切换到国内镜像。
    awk -v apt_mirror="$APT_MIRROR_URL" '
        /^RUN --mount=type=cache,target=\/root\/.m2[[:space:]]*\\$/ {
            print
            print "    --mount=type=secret,id=maven-settings,target=/root/.m2/settings.xml \\"
            print "    sed -i -E '\''s@https?://(archive|security).ubuntu.com/ubuntu@" apt_mirror "@g'\'' /etc/apt/sources.list 2>/dev/null || true && \\"
            next
        }
        { print }
    ' "$source_file" > "$output_file"
}

create_maven_settings() {
    local settings_file="$1"

    cat > "$settings_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
  <mirrors>
    <mirror>
      <id>china-mainland-mirror</id>
      <url>https://maven.aliyun.com/repository/public</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
EOF
}

main() {
    local arch="amd64"
    local custom_tag=""
    local no_cache=false
    local short_sha
    local build_args
    local temp_dir
    local build_dockerfile
    local maven_settings

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_usage
                return 0
                ;;
            -a|--arch)
                if [[ $# -lt 2 || ( "$2" != "amd64" && "$2" != "arm64" ) ]]; then
                    print_error "--arch 只支持 amd64 或 arm64"
                    return 1
                fi
                arch="$2"
                shift 2
                ;;
            -t|--tag)
                if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                    print_error "--tag 需要一个非空值"
                    return 1
                fi
                custom_tag="$2"
                shift 2
                ;;
            -n|--no-cache)
                no_cache=true
                shift
                ;;
            *)
                print_error "未知参数：$1"
                show_usage
                return 1
                ;;
        esac
    done

    cd "$PROJECT_ROOT"
    if [[ ! -f Dockerfile ]]; then
        print_error "项目根目录下未找到 Dockerfile"
        return 1
    fi
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker 未运行或无法访问"
        return 1
    fi

    print_info "目标架构：linux/${arch}；镜像：${IMAGE_NAME}:latest"
    print_info "Ubuntu 软件源：${APT_MIRROR_URL}"
    pull_base_images "$arch"

    temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/wespring-auth-local.XXXXXX")"
    trap 'rm -rf "${temp_dir}"' EXIT
    build_dockerfile="${temp_dir}/Dockerfile"
    maven_settings="${temp_dir}/settings.xml"
    create_maven_settings "$maven_settings"
    prepare_dockerfile Dockerfile "$build_dockerfile"

    short_sha="$(git rev-parse --short HEAD 2>/dev/null || echo local)"
    build_args=(--file "$build_dockerfile" --platform "linux/${arch}" --secret "id=maven-settings,src=${maven_settings}" --tag "${IMAGE_NAME}:latest")
    if [[ -n "$custom_tag" ]]; then
        build_args+=(--tag "${IMAGE_NAME}:${custom_tag}")
    else
        build_args+=(--tag "${IMAGE_NAME}:sha-${short_sha}")
    fi
    if [[ "$no_cache" == true ]]; then
        build_args+=(--no-cache)
    fi

    print_info "开始构建：docker build ${build_args[*]} ."
    docker build "${build_args[@]}" .
    print_info "构建完成：${IMAGE_NAME}:latest (linux/${arch})"
    docker images "$IMAGE_NAME" --format 'table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}'
}

main "$@"
