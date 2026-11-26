#!/usr/bin/env bash

# 获取所有测试用户的 JWT 令牌（支持可选：刷新 与 解码打印）
# 基于 test.sh 脚本的 OAuth2 授权流程

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
OUTPUT_FILE="${OUTPUT_FILE:-$SCRIPT_DIR/all-test-tokens.env}"
BASE_URL="${BASE_URL:-http://localhost:9000}"

# 选项默认值（均为关闭，以避免对本地环境造成副作用）
ENABLE_REFRESH=0
PRINT_DECODED=0

usage() {
    cat <<'EOF'
用法:
  ./get-test-user-tokens.sh [OPTIONS]

选项（默认全部关闭）:
  -r, --refresh         在获取后尝试刷新一次，并保存刷新后的最新令牌
  -d, --decode          打印每个用户最终 access token 的解码结果（含 groups/authorities）
  -o, --output PATH     指定汇总输出文件路径（默认: scripts/all-test-tokens.env）
  -h, --help            显示本帮助并退出

环境变量:
  BASE_URL              授权服务器地址（默认: http://localhost:9000）
  OUTPUT_FILE           汇总输出文件路径（优先级低于 --output）

说明:
  - 通过 TEST_USERNAME / TEST_PASSWORD / TEST_BASE_URL / TEST_OUTPUT_DIR 驱动 test.sh，
    不修改任何脚本文件，且临时产物隔离在 mktemp 目录中，退出自动清理；
  - 汇总文件采用原子替换写入（权限 600），全部失败时不会破坏已有文件；
  - 只要有用户获取失败即返回非零退出码，便于 dev.sh / CI 准确感知。
EOF
}

# 先解析命令行参数（--help 不输出 banner、不依赖 test.sh）
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--refresh)
            ENABLE_REFRESH=1
            shift
            ;;
        -d|--decode)
            PRINT_DECODED=1
            shift
            ;;
        -o|--output)
            [[ $# -ge 2 ]] || { echo "❌ --output 需要一个文件路径" >&2; exit 2; }
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --output=*)
            OUTPUT_FILE="${1#*=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "❌ 未知选项: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[ -f "$SCRIPT_DIR/test.sh" ] || { echo "❌ 找不到 test.sh: $SCRIPT_DIR/test.sh" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "❌ 缺少依赖命令: jq" >&2; exit 1; }

# 独立临时目录，用于隔离每次运行及每个用户的中间文件
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

TMP_ENV_FILE="$TMP_DIR/all-test-tokens.env"

# 跨平台 Base64 解码（兼容 macOS BSD base64 与 GNU base64，不强依赖 gbase64）
base64_decode() {
    if printf 'QQ==' | base64 -d >/dev/null 2>&1; then
        base64 -d
    elif printf 'QQ==' | base64 -D >/dev/null 2>&1; then
        base64 -D
    elif command -v gbase64 >/dev/null 2>&1; then
        gbase64 -d
    else
        return 1
    fi
}

decode_jwt() {
    local jwt_part="$1"
    local rem=$(( ${#jwt_part} % 4 ))
    if [ "$rem" -eq 2 ]; then
        jwt_part="${jwt_part}=="
    elif [ "$rem" -eq 3 ]; then
        jwt_part="${jwt_part}="
    fi
    printf '%s' "$jwt_part" | tr '_-' '/+' | base64_decode 2>/dev/null
}

# 函数：获取单个用户的令牌
get_user_token() {
    local username="$1"
    local password="$2"
    local user_tmp="$TMP_DIR/$username"
    local user_log="$user_tmp/test.log"
    local token_file="$user_tmp/tokens.env"
    local access_token=""
    local refresh_token=""
    local refresh_flag="false"
    local note="初次获取"

    mkdir -p "$user_tmp"
    if [[ "$ENABLE_REFRESH" == "1" ]]; then
        refresh_flag="true"
        note="已刷新"
    fi

    echo "🔄 正在获取用户 $username 的令牌..."

    if ! TEST_BASE_URL="$BASE_URL" \
         TEST_USERNAME="$username" \
         TEST_PASSWORD="$password" \
         TEST_REFRESH_TOKEN="$refresh_flag" \
         TEST_OUTPUT_DIR="$user_tmp" \
         bash "$SCRIPT_DIR/test.sh" >"$user_log" 2>&1; then
        echo "❌ 获取用户 $username 的令牌失败" >&2
        if [ -s "$user_log" ]; then
            echo "   最近错误输出:" >&2
            grep -E '❌|Error|failed|HTTP ' "$user_log" | tail -n 5 | sed 's/^/   | /' >&2 || \
                tail -n 5 "$user_log" | sed 's/^/   | /' >&2
        fi
        return 1
    fi

    if [ ! -f "$token_file" ]; then
        echo "❌ 获取用户 $username 的令牌失败（未生成 tokens.env）" >&2
        return 1
    fi

    # 在隔离的 subshell 中安全读取 tokens.env（兼容引号与含 = 的值）
    access_token="$(env -i bash -c 'source "$1" && printf "%s" "${ACCESS_TOKEN:-}"' _ "$token_file")"
    refresh_token="$(env -i bash -c 'source "$1" && printf "%s" "${REFRESH_TOKEN:-}"' _ "$token_file")"

    if [ -z "$access_token" ]; then
        echo "❌ 获取用户 $username 的令牌失败（ACCESS_TOKEN 为空）" >&2
        return 1
    fi

    local upper_username
    upper_username="$(printf '%s' "$username" | tr '[:lower:]' '[:upper:]')"
    echo "✅ 成功获取用户 $username 的令牌"

    # 可选：解码并显示该用户最终 access token 的 Claims
    if [[ "$PRINT_DECODED" == "1" ]]; then
        echo "📝 $username 解码后的 Access Token Claims:"
        local payload payload_decoded groups authorities
        payload="$(printf '%s' "$access_token" | cut -d'.' -f2)"
        payload_decoded="$(decode_jwt "$payload" || true)"
        if [ -n "$payload_decoded" ]; then
            printf '%s\n' "$payload_decoded" | jq '.' 2>/dev/null || printf '%s\n' "$payload_decoded"
            groups="$(printf '%s' "$payload_decoded" | jq -r '.groups // empty' 2>/dev/null || true)"
            if [ -n "$groups" ] && [ "$groups" != "null" ]; then
                echo "✅ groups:"
                printf '%s\n' "$groups" | jq '.' 2>/dev/null || printf '%s\n' "$groups"
            else
                echo "⚠️  groups 缺失"
            fi
            authorities="$(printf '%s' "$payload_decoded" | jq -r '.authorities // empty' 2>/dev/null || true)"
            if [ -n "$authorities" ] && [ "$authorities" != "null" ]; then
                echo "✅ authorities:"
                printf '%s\n' "$authorities" | jq '.' 2>/dev/null || printf '%s\n' "$authorities"
            else
                echo "⚠️  authorities 缺失（若用户无直接权限这是正常的）"
            fi
        else
            echo "❌ 无法解码 Access Token" >&2
        fi
    fi

    # 写入临时汇总文件（使用 %q 防止特殊字符注入）
    {
        echo "# $username 用户的令牌 ($note)"
        printf 'export %s_ACCESS_TOKEN=%q\n' "$upper_username" "$access_token"
        if [ -n "$refresh_token" ] && [ "$refresh_token" != "null" ]; then
            printf 'export %s_REFRESH_TOKEN=%q\n' "$upper_username" "$refresh_token"
        fi
        echo ""
    } >> "$TMP_ENV_FILE"

    return 0
}

echo "🚀 获取所有测试用户的 JWT 令牌"
echo "========================================"
echo "   目标服务: $BASE_URL"
echo ""

{
    echo "# 所有测试用户的 JWT 令牌"
    echo "# 目标服务: $BASE_URL"
    echo "# 生成时间: $(date)"
    echo ""
} > "$TMP_ENV_FILE"

# 测试用户列表
users=(
    "hq_admin:hq123"
    "distributor_admin:dist123"
    "store_admin:store123"
    "consultant:cons123"
    "distributor_employee:emp123"
)

success_count=0
total_count=${#users[@]}

for user_info in "${users[@]}"; do
    username="${user_info%%:*}"
    password="${user_info#*:}"

    if get_user_token "$username" "$password"; then
        success_count=$((success_count + 1))
    fi
done

echo ""
echo "🎉 完成！成功获取 $success_count/$total_count 个用户的令牌"

if [ "$success_count" -gt 0 ]; then
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    chmod 600 "$TMP_ENV_FILE"
    mv "$TMP_ENV_FILE" "$OUTPUT_FILE"

    echo ""
    echo "========================================"
    echo "📋 当前所有可用测试 Token（source 即可使用）"
    echo "========================================"
    grep '^export ' "$OUTPUT_FILE" || true
    echo ""
    echo "📁 所有令牌已保存到: $OUTPUT_FILE"
    echo ""
    echo "使用方法:"
    echo "  source $OUTPUT_FILE"
    echo "  echo \$HQ_ADMIN_ACCESS_TOKEN"
else
    echo "❌ 未获取到任何可用令牌（未覆盖 $OUTPUT_FILE）。" >&2
fi

if [ "$success_count" -lt "$total_count" ]; then
    exit 1
fi
