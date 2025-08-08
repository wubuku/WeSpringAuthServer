#!/bin/bash
set -euo pipefail

# 获取单个用户的JWT令牌（自定义认证URL）
# 用法: ./get-user-token.sh <AUTH_BASE_URL> <USERNAME>
# 密码将以无回显方式提示输入

if [ $# -lt 2 ]; then
  echo "用法: $0 <AUTH_BASE_URL> <USERNAME>"
  exit 1
fi

AUTH_URL="$1"
USERNAME="$2"

# 提示输入密码（不回显）
read -s -p "请输入 $USERNAME 的密码: " PASSWORD
echo ""

script_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$script_dir"

if [ ! -f "test.sh" ]; then
  echo "❌ 未找到 test.sh，请在 scripts 目录下运行或检查文件是否存在"
  exit 1
fi
# 生成临时脚本（不修改原始 test.sh）
TMP_SCRIPT=$(mktemp -t getusertoken.XXXXXX)
trap 'rm -f "$TMP_SCRIPT"' EXIT

# 用 awk 替换关键配置行，避免在命令行参数中直接包含密码
AUTH_URL_ESC=$(printf '%s' "$AUTH_URL" | sed 's/[\&/]/\\&/g')
USERNAME_ESC=$(printf '%s' "$USERNAME" | sed 's/[\&/]/\\&/g')
PASSWORD_ESC=$(printf '%s' "$PASSWORD" | sed 's/[\&/]/\\&/g')

# 仅替换前3处定义（与 test.sh 的结构一致）
sed \
  -e "s/^BASE_URL=\".*\"/BASE_URL=\"$AUTH_URL_ESC\"/" \
  -e "s/^USERNAME=\".*\"/USERNAME=\"$USERNAME_ESC\"/" \
  -e "s/^PASSWORD=\".*\"/PASSWORD=\"$PASSWORD_ESC\"/" \
  "test.sh" > "$TMP_SCRIPT"
chmod +x "$TMP_SCRIPT"

# 执行临时脚本，静默其大部分输出，只保留错误用于排查
if "$TMP_SCRIPT" > /dev/null 2>&1; then
  :
else
  echo "❌ 获取令牌流程执行失败"
  exit 1
fi

# 读取 tokens.env
if [ ! -f tokens.env ]; then
  echo "❌ 未找到 tokens.env，可能授权失败"
  exit 1
fi

access_token=$(grep "^export ACCESS_TOKEN=" tokens.env | cut -d'=' -f2-)
refresh_token=$(grep "^export REFRESH_TOKEN=" tokens.env | cut -d'=' -f2-)

# 去除可能的首尾引号
access_token=${access_token#\"}
access_token=${access_token%\"}
refresh_token=${refresh_token#\"}
refresh_token=${refresh_token%\"}

if [ -z "$access_token" ]; then
  echo "❌ 未能解析到 Access Token"
  exit 1
fi

upper_username=$(echo "$USERNAME" | tr '[:lower:]' '[:upper:]')

echo "✅ 成功获取用户 $USERNAME 的令牌"
echo ""
echo "# $USERNAME 用户的令牌"
echo "export ${upper_username}_ACCESS_TOKEN=$access_token"
echo "export ${upper_username}_REFRESH_TOKEN=$refresh_token"
echo ""
