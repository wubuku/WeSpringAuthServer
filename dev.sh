#!/usr/bin/env bash
# ============================================================
# WeSpringAuthServer 本地 dev 启动脚本（替代 IntelliJ IDEA Run Configuration）
#
# 等价关系（对照 .idea/workspace.xml 中 Application.AuthServerApplication）：
#   - 主类：org.dddml.ffvtraceability.auth.AuthServerApplication
#   - 工作目录：$PROJECT_DIR（本脚本所在目录）
#   - 环境变量文件：$PROJECT_DIR/.env（source 后 export，与 IDEA EnvFile 插件一致）
#   - profile：dev（application.yml 的默认值，显式传入避免外部覆盖）
#   - JDK：优先对齐 IDEA 项目 SDK（JDK 24），避免使用 PATH 上的 JDK 25（Lombok 可能不兼容）
#
# 用法：
#   ./dev.sh                         增量构建并以 dev profile 启动（默认端口 9000，后台运行）
#   ./dev.sh --port 9001             指定端口（等价 SERVER_PORT=9001）
#   ./dev.sh --force-kill            强杀目标端口上的任意监听进程后再启动
#   ./dev.sh clean                   先 mvn clean 再构建启动
#   ./dev.sh --no-build              跳过构建，直接用 target 下已有的 jar 启动
#   ./dev.sh --foreground            前台运行，日志直出终端，Ctrl-C 停止（最接近 IDEA Run 窗口）
#   ./dev.sh stop [--port N]         停止本脚本管理的进程
#   ./dev.sh stop --port N --force-kill  强杀指定端口上的任意监听进程
#   ./dev.sh restart [--port N]      停止后重新启动
#   ./dev.sh status [--port N]       查看运行中的 dev 实例
#   ./dev.sh logs [--port N]         跟踪某个实例的日志
#   ./dev.sh --help                  完整帮助
#
# 运行产物都在 target/dev/ 下（已被 .gitignore 覆盖）：
#   auth-server-<port>.pid / auth-server-<port>.log
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
cd "$SCRIPT_DIR"

MAIN_CLASS="org.dddml.ffvtraceability.auth.AuthServerApplication"
ARTIFACT_PREFIX="ffvtraceability-auth-server"
HEALTH_PATH="/health"
STARTUP_TIMEOUT=180

ACTION="start"
ACTION_SET=false
PORT_ARG=""
FORCE_KILL=false
CLEAN_BUILD=false
NO_BUILD=false
FOREGROUND=false
NO_HEALTH_CHECK=false
TIMEOUT_ARG=""
ENV_FILE="${DEV_ENV_FILE:-$SCRIPT_DIR/.env}"
JAVA_HOME_OVERRIDE="${DEV_JAVA_HOME:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./dev.sh [start|clean|stop|restart|status|logs] [options]

Actions:
  start      增量构建并启动（默认；后台运行）
  clean      先 mvn clean 再构建启动
  stop       停止本脚本管理的 dev 实例（不带 --port 时停止所有实例）
  restart    先 stop 再 start
  status     查看 dev 实例状态（不带 --port 时列出所有实例）
  logs       tail -f 实例日志

Options:
  --port N, -p N       指定端口（默认取 .env 的 SERVER_PORT，否则 9000）
  --force-kill         强杀目标端口上的任意监听进程（仅用于确实要清理时）
  --no-build           跳过 Maven 构建，使用 target 下已有的 jar
  --foreground, -f     前台运行：日志直出终端，Ctrl-C 停止（不等待健康检查）
  --env-file PATH      环境变量文件（默认 $PROJECT_DIR/.env）
  --java-home PATH     指定 JDK HOME（默认优先 JDK 24，对齐 IDEA 项目 SDK）
  --timeout N          启动健康检查超时秒数（默认 180）
  --no-health-check    不等待 /health 就绪，启动后立即返回
  -h, --help, help     显示本帮助

Examples:
  ./dev.sh
  ./dev.sh --port 9001 --force-kill
  ./dev.sh clean --port 9000
  ./dev.sh --no-build --foreground
  ./dev.sh stop
  ./dev.sh logs --port 9001
EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "$*"; }
progress() { printf '%s' "$*"; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    start|clean|stop|restart|status|logs)
      [ "$ACTION_SET" = false ] || die "只能指定一个 action"
      ACTION="$1"
      ACTION_SET=true
      shift
      ;;
    --port|-p)
      [ "$#" -ge 2 ] || die "--port 需要一个端口号"
      PORT_ARG="$2"
      shift 2
      ;;
    --port=*)
      PORT_ARG="${1#*=}"
      shift
      ;;
    --force-kill)
      FORCE_KILL=true
      shift
      ;;
    --no-build)
      NO_BUILD=true
      shift
      ;;
    --foreground|-f)
      FOREGROUND=true
      shift
      ;;
    --no-health-check)
      NO_HEALTH_CHECK=true
      shift
      ;;
    --env-file)
      [ "$#" -ge 2 ] || die "--env-file 需要一个路径"
      ENV_FILE="$2"
      shift 2
      ;;
    --env-file=*)
      ENV_FILE="${1#*=}"
      shift
      ;;
    --java-home)
      [ "$#" -ge 2 ] || die "--java-home 需要一个 JDK HOME 路径"
      JAVA_HOME_OVERRIDE="$2"
      shift 2
      ;;
    --java-home=*)
      JAVA_HOME_OVERRIDE="${1#*=}"
      shift
      ;;
    --timeout)
      [ "$#" -ge 2 ] || die "--timeout 需要秒数"
      TIMEOUT_ARG="$2"
      shift 2
      ;;
    --timeout=*)
      TIMEOUT_ARG="${1#*=}"
      shift
      ;;
    -h|--help|help)
      [ "$ACTION_SET" = false ] || die "help 不能与其他 action 组合"
      usage
      exit 0
      ;;
    *)
      echo "未知参数: $1" >&2
      usage
      exit 2
      ;;
  esac
done

case "$ACTION" in
  clean)
    CLEAN_BUILD=true
    ACTION=start
    ;;
esac

if [ "$ACTION" != "start" ] && [ "$ACTION" != "stop" ] && [ "$ACTION" != "restart" ] \
   && [ "$ACTION" != "status" ] && [ "$ACTION" != "logs" ]; then
  die "不支持的 action: $ACTION"
fi

if [ "$FOREGROUND" = true ]; then
  [ "$ACTION" = "start" ] || die "--foreground 只能用于 start"
  [ "$NO_HEALTH_CHECK" = false ] || die "--foreground 与 --no-health-check 不要同时使用"
fi
if [ "$CLEAN_BUILD" = true ] && [ "$NO_BUILD" = true ]; then
  die "clean 与 --no-build 不能同时使用"
fi

command -v lsof >/dev/null 2>&1 || die "需要 lsof（macOS 自带）来做端口检查"
command -v curl >/dev/null 2>&1 || die "需要 curl 来做启动健康检查"

RUN_DIR="$SCRIPT_DIR/target/dev"
mkdir -p "$RUN_DIR"

pid_file_for() { printf '%s/auth-server-%s.pid' "$RUN_DIR" "$1"; }
log_file_for() { printf '%s/auth-server-%s.log' "$RUN_DIR" "$1"; }

listeners_on_port() {
  lsof -nP -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null || true
}

pid_listens_on_port() {
  [ -n "${1:-}" ] && [ -n "${2:-}" ] || return 1
  lsof -nP -a -p "$1" -iTCP:"$2" -sTCP:LISTEN >/dev/null 2>&1
}

process_cwd() {
  lsof -a -p "$1" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1
}

process_cmd() {
  ps -p "$1" -o command= 2>/dev/null | sed 's/^[[:space:]]*//' | cut -c1-160
}

# ---------- JDK 解析：优先对齐 IDEA 项目 SDK ----------

java_spec_major() {
  local spec=""
  spec="$("$1" -XshowSettings:properties -version 2>&1 \
    | sed -n 's/^[[:space:]]*java.specification.version = //p' | head -n 1)"
  case "$spec" in
    1.*) printf '%s\n' "${spec#1.}" | cut -d. -f1 ;;
    *)   printf '%s\n' "$spec" | cut -d. -f1 ;;
  esac
}

usable_jdk_home() {
  local home="$1" major=""
  [ -n "$home" ] && [ -x "$home/bin/java" ] || return 1
  major="$(java_spec_major "$home/bin/java")"
  [ -n "$major" ] || return 1
  # 自动选择只接受 17~24；JDK 25 与当前 Lombok 版本的兼容性未验证。
  [ "$major" -ge 17 ] && [ "$major" -le 24 ] || return 1
  printf '%s\n' "$home"
}

resolve_jdk() {
  local candidate="" major=""

  if [ -n "$JAVA_HOME_OVERRIDE" ]; then
    [ -x "$JAVA_HOME_OVERRIDE/bin/java" ] || die "--java-home 不是有效的 JDK: $JAVA_HOME_OVERRIDE"
    major="$(java_spec_major "$JAVA_HOME_OVERRIDE/bin/java")"
    [ -n "$major" ] && [ "$major" -ge 17 ] || die "--java-home 指向的 JDK 版本过低（需 >= 17）: major=${major:-unknown}"
    if [ "$major" -gt 24 ]; then
      echo "WARNING: 显式指定的 JDK major=$major 高于 24；当前 Lombok 版本可能不支持，构建失败请换 JDK 21/24。" >&2
    fi
    printf '%s\n' "$JAVA_HOME_OVERRIDE"
    return 0
  fi

  # 1) IDEA 项目 SDK 是 openjdk-24；2) 退而求其次 21 / 17；3) 已有 JAVA_HOME；4) PATH。
  for candidate in \
    "$(/usr/libexec/java_home -v 24 2>/dev/null || true)" \
    "$(/usr/libexec/java_home -v 21 2>/dev/null || true)" \
    "$(/usr/libexec/java_home -v 17 2>/dev/null || true)" \
    "${JAVA_HOME:-}" \
    "$(dirname "$(dirname "$(command -v java 2>/dev/null || true)")" 2>/dev/null || true)"; do
    if resolved="$(usable_jdk_home "$candidate")"; then
      printf '%s\n' "$resolved"
      return 0
    fi
  done

  echo "ERROR: 找不到可用的 JDK 17~24（本机 PATH 上的 Java 可能是 25，Lombok 不兼容）。" >&2
  echo "       可用 --java-home / DEV_JAVA_HOME 显式指定，或安装 JDK 21/24。" >&2
  exit 1
}

export JAVA_HOME="$(resolve_jdk)"
export PATH="$JAVA_HOME/bin:$PATH"
JAVA_BIN="$JAVA_HOME/bin/java"
JDK_MAJOR="$(java_spec_major "$JAVA_BIN")"

# ---------- 环境变量：与 IDEA EnvFile 插件等价 ----------

load_env_file() {
  [ -f "$ENV_FILE" ] || die "环境变量文件不存在: $ENV_FILE"
  info "  环境文件: $ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
}

resolve_port() {
  local port="${PORT_ARG:-${SERVER_PORT:-9000}}"
  case "$port" in
    ''|*[!0-9]*) die "端口必须是正整数: $port" ;;
  esac
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    die "端口超出范围 (1-65535): $port"
  fi
  printf '%s\n' "$port"
}

if [ "$TIMEOUT_ARG" != "" ]; then
  case "$TIMEOUT_ARG" in
    ''|*[!0-9]*) die "--timeout 必须是正整数秒数" ;;
  esac
  [ "$TIMEOUT_ARG" -gt 0 ] || die "--timeout 必须大于 0"
  STARTUP_TIMEOUT="$TIMEOUT_ARG"
fi

# ---------- 进程治理 ----------

stop_managed_instance() {
  local port="$1" pidfile="${2:-}" pid="" cwd=""
  [ -f "$pidfile" ] || return 0
  pid="$(tr -d '[:space:]' < "$pidfile")"
  if ! [[ "$pid" =~ ^[0-9]+$ ]] || ! kill -0 "$pid" 2>/dev/null; then
    info "  清理过期 PID 文件: $pidfile (pid=${pid:-empty})"
    rm -f "$pidfile"
    return 0
  fi
  # PID 文件按端口命名；若进程实际监听别的端口，绝不误杀。
  if ! pid_listens_on_port "$pid" "$port"; then
    info "  忽略 PID ${pid}：未监听端口 ${port}（PID 文件保留）"
    return 0
  fi
  cwd="$(process_cwd "$pid")"
  if [ "$cwd" != "$SCRIPT_DIR" ]; then
    info "  忽略 PID ${pid}：工作目录不匹配 (${cwd:-unknown})，PID 文件保留"
    return 0
  fi

  info "  停止本脚本管理的实例: PID=$pid, port=$port"
  kill "$pid" 2>/dev/null || true
  local waited=0
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 10 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$pidfile"
}

force_kill_port() {
  local port="$1" pids="" pid=""
  pids="$(listeners_on_port "$port")"
  [ -n "$pids" ] || return 0
  for pid in $pids; do
    echo "  [FORCE-KILL] port=$port pid=$pid cwd=$(process_cwd "$pid") cmd=$(process_cmd "$pid")" >&2
  done
  # shellcheck disable=SC2086
  kill -9 $pids 2>/dev/null || true
  sleep 1
  if [ -n "$(listeners_on_port "$port")" ]; then
    die "端口 $port 在 --force-kill 之后仍被占用"
  fi
  rm -f "$(pid_file_for "$port")"
}

ensure_port_available() {
  local port="$1" pidfile="" pids="" recorded="" cwd=""
  pids="$(listeners_on_port "$port")"
  [ -n "$pids" ] || return 0
  pidfile="$(pid_file_for "$port")"

  if [ "$FORCE_KILL" = true ]; then
    force_kill_port "$port"
    return 0
  fi

  # 默认只允许自动清理"本脚本启动、且确实监听该端口、且工作目录匹配"的实例。
  if [ -f "$pidfile" ]; then
    recorded="$(tr -d '[:space:]' < "$pidfile")"
    if [[ "$recorded" =~ ^[0-9]+$ ]] && pid_listens_on_port "$recorded" "$port"; then
      cwd="$(process_cwd "$recorded")"
      if [ "$cwd" = "$SCRIPT_DIR" ]; then
        stop_managed_instance "$port" "$pidfile"
        return 0
      fi
    fi
  fi

  echo "ERROR: 端口 $port 已被占用，当前监听者：" >&2
  for pid in $pids; do
    echo "  pid=$pid cwd=$(process_cwd "$pid") cmd=$(process_cmd "$pid")" >&2
  done
  echo "  如确认需要终止，请加 --force-kill 重试。" >&2
  exit 1
}

collect_pid_files() {
  local f=""
  for f in "$RUN_DIR"/auth-server-*.pid; do
    if [ -f "$f" ]; then
      printf '%s\n' "$f"
    fi
  done
  return 0
}

# ---------- 子命令：status / logs / stop ----------

health_code() {
  curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 3 \
    "http://127.0.0.1:$1$HEALTH_PATH" 2>/dev/null || true
}

cmd_status() {
  local files="" f="" port="" pid="" code=""
  if [ -n "$PORT_ARG" ]; then
    f="$(pid_file_for "$(resolve_port)")"
    [ -f "$f" ] && files="$f"
  else
    files="$(collect_pid_files)"
  fi

  if [ -z "$files" ]; then
    info "没有 dev.sh 管理的实例（PID 文件目录: ${RUN_DIR}）"
    return 0
  fi

  echo "=== WeSpringAuthServer dev instances ==="
  for f in $files; do
    port="$(basename "$f" .pid)"
    port="${port#auth-server-}"
    pid="$(tr -d '[:space:]' < "$f")"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null && pid_listens_on_port "$pid" "$port"; then
      code="$(health_code "$port")"
      info "  RUNNING  port=$port pid=$pid health=HTTP ${code:-N/A} cwd=$(process_cwd "$pid")"
      info "           log: $(log_file_for "$port")"
    else
      info "  STALE    port=$port pid=${pid:-empty}（PID 文件将在下次 stop 时清理）"
    fi
  done
}

cmd_logs() {
  local port="" logfile=""
  port="$(resolve_port)"
  logfile="$(log_file_for "$port")"
  [ -f "$logfile" ] || die "没有找到日志: $logfile"
  info "跟踪日志: ${logfile}（Ctrl-C 退出）"
  tail -n 100 -f "$logfile"
}

cmd_stop() {
  local port="" f=""
  if [ "$FORCE_KILL" = true ]; then
    # 强杀模式必须明确目标端口；未指定则用默认端口，避免误杀无关端口。
    port="$(resolve_port)"
    info "[stop] 强杀端口 $port 上的监听进程..."
    force_kill_port "$port"
    info "[stop] 完成。"
    return 0
  fi

  if [ -n "$PORT_ARG" ]; then
    port="$(resolve_port)"
    info "[stop] 停止端口 $port 上由 dev.sh 管理的实例..."
    stop_managed_instance "$port" "$(pid_file_for "$port")"
  else
    info "[stop] 停止所有由 dev.sh 管理的实例..."
    for f in $(collect_pid_files); do
      port="$(basename "$f" .pid)"
      port="${port#auth-server-}"
      stop_managed_instance "$port" "$f"
    done
  fi
  info "[stop] 完成。"
}

# ---------- 启动 ----------

build_jar() {
  if [ "$NO_BUILD" = true ]; then
    BUILD_JAR="$(find "$SCRIPT_DIR/target" -maxdepth 1 -type f \
      -name "${ARTIFACT_PREFIX}-*.jar" ! -name '*-original.jar' -print -quit)"
    [ -n "$BUILD_JAR" ] || die "--no-build 但 target 下没有 ${ARTIFACT_PREFIX}-*.jar，请先运行 ./dev.sh 构建"
  else
    info "[2/5] 构建（增量，跳过测试）..."
    if [ "$CLEAN_BUILD" = true ]; then
      ./mvnw -B -ntp -Dmaven.test.skip=true clean package
    else
      ./mvnw -B -ntp -Dmaven.test.skip=true package
    fi
    BUILD_JAR="$(find "$SCRIPT_DIR/target" -maxdepth 1 -type f \
      -name "${ARTIFACT_PREFIX}-*.jar" ! -name '*-original.jar' -print -quit)"
    [ -n "$BUILD_JAR" ] || die "构建成功但 target 下没有找到 ${ARTIFACT_PREFIX}-*.jar"
  fi
}

wait_for_ready() {
  local port="$1" pid="$2" logfile="$3" waited=0 code="" last_marker
  progress "  等待 $HEALTH_PATH 就绪..."
  while [ "$waited" -lt "$STARTUP_TIMEOUT" ]; do
    sleep 2
    waited=$((waited + 2))

    if ! kill -0 "$pid" 2>/dev/null; then
      echo " FAILED"
      echo "  ERROR: 应用进程已退出（PID=${pid}）" >&2
      tail -n 80 "$logfile" >&2 || true
      rm -f "$(pid_file_for "$port")"
      exit 1
    fi

    last_marker="$(grep -E 'APPLICATION FAILED TO START|Application run failed|Web server failed to start|Error starting ApplicationContext' \
      "$logfile" 2>/dev/null | tail -n 1 || true)"
    if [ -n "$last_marker" ]; then
      echo " FAILED"
      echo "  ERROR: 应用启动失败: $last_marker" >&2
      tail -n 80 "$logfile" >&2 || true
      stop_managed_instance "$port" "$(pid_file_for "$port")"
      exit 1
    fi

    code="$(health_code "$port")"
    if [ "$code" = "200" ]; then
      echo " ready!"
      return 0
    fi
    progress "."
  done

  echo " TIMEOUT"
  echo "  ERROR: ${STARTUP_TIMEOUT}s 内未就绪，最后 HTTP 状态码: ${code:-N/A}" >&2
  echo "  常见原因：数据库未启动 / .env 配置错误 / 端口被防火墙拦截" >&2
  tail -n 80 "$logfile" >&2 || true
  stop_managed_instance "$port" "$(pid_file_for "$port")"
  exit 1
}

cmd_start() {
  local port="" pidfile="" logfile="" pid=""

  echo "=== WeSpringAuthServer dev (profile=dev) ==="

  info "[1/5] 检查环境..."
  info "  JDK: $JAVA_HOME (major=$JDK_MAJOR)"
  info "  工作目录: $SCRIPT_DIR"
  load_env_file
  port="$(resolve_port)"
  export SERVER_PORT="$port"
  export SPRING_PROFILES_ACTIVE="dev"
  # 应用的 JWT/OIDC issuer 默认是 http://localhost:9000；自定义端口时同步调整，
  # 避免 resource server 校验 iss 或 OIDC 元数据时指向错误地址。.env 显式指定则尊重。
  if [ "$port" != "9000" ] && [ -z "${AUTH_SERVER_ISSUER:-}" ]; then
    export AUTH_SERVER_ISSUER="http://localhost:$port"
    info "  Issuer: ${AUTH_SERVER_ISSUER}（随端口自动调整）"
  fi
  pidfile="$(pid_file_for "$port")"
  logfile="$(log_file_for "$port")"
  info "  端口: $port"
  info "  PID 文件: $pidfile"
  info "  日志文件: $logfile"

  ensure_port_available "$port"

  build_jar

  info "[3/5] 启动应用..."
  mkdir -p "$RUN_DIR"
  : > "$logfile"

  if [ "$FOREGROUND" = true ]; then
    info "  前台模式：日志直接输出到终端，Ctrl-C 停止。"
    echo "$$" > "$pidfile"
    exec "$JAVA_BIN" -jar "$BUILD_JAR" \
      --spring.profiles.active=dev \
      --server.port="$port"
  fi

  nohup "$JAVA_BIN" -jar "$BUILD_JAR" \
    --spring.profiles.active=dev \
    --server.port="$port" \
    </dev/null >"$logfile" 2>&1 &
  pid=$!
  echo "$pid" > "$pidfile"
  info "  PID: $pid"

  info "[4/5] 健康检查..."
  if [ "$NO_HEALTH_CHECK" = true ]; then
    info "  已跳过（--no-health-check）"
  else
    wait_for_ready "$port" "$pid" "$logfile"
  fi

  info "[5/5] 完成。"
  echo ""
  echo "=== Dev Server Ready ==="
  echo "  Base URL: http://localhost:$port"
  echo "  Health:   http://localhost:$port$HEALTH_PATH"
  echo "  OIDC:     http://localhost:$port/.well-known/openid-configuration"
  echo "  PID:      $pid"
  echo "  Log:      $logfile"
  echo "  Stop:     ./dev.sh stop --port $port"
  echo "  Follow:   ./dev.sh logs --port $port"
}

# 尽早校验显式端口，避免把参数错误拖到构建之后才发现。
if [ -n "$PORT_ARG" ]; then
  resolve_port >/dev/null
fi

case "$ACTION" in
  status)  cmd_status ;;
  logs)    cmd_logs ;;
  stop)    cmd_stop ;;
  start)   cmd_start ;;
  restart)
    cmd_stop
    ACTION=start
    # restart 沿用 stop 时解析出的端口；未显式指定则不使用旧的 PID 文件。
    cmd_start
    ;;
esac
