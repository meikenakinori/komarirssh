#!/bin/bash

#================================================================================
# Komari Monitor RS 增强安装脚本
#
# 功能:
#   - 支持自动发现 (Auto Discovery) 机制 - 在 shell 中实现完整注册流程
#   - 跨平台支持 (Linux/macOS/FreeBSD/OpenWrt)
#   - 多种 init 系统支持 (systemd/OpenRC/procd/launchd/upstart)
#   - 自动架构检测和二进制下载
#   - 智能配置管理
#
# 使用方法:
#   1. 自动发现模式 (推荐):
#      bash install.sh --endpoint https://your.server.com --auto-discovery-key YOUR_KEY
#   2. 传统 Token 模式:
#      bash install.sh --http-server "http://your.server:port" --token "your_token"
#================================================================================

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# --- 日志函数 ---
log_info() {
    echo -e "${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${NC} $1"
}

log_config() {
    echo -e "${CYAN}[CONFIG]${NC} $1"
}

# --- 默认配置 ---
service_name="komari-agent-rs"
target_dir="/opt/komari-rs"
github_proxy=""
install_version=""
GITHUB_REPO="GenshinMinecraft/komari-monitor-rs"

# --- 检测操作系统 ---
os_type=$(uname -s)
case $os_type in
    Darwin)
        os_name="darwin"
        target_dir="/usr/local/komari-rs"
        if [ ! -w "/usr/local" ] && [ "$EUID" -ne 0 ]; then
            target_dir="$HOME/.komari-rs"
            log_info "No write permission to /usr/local, using user directory: $target_dir"
        fi
        ;;
    Linux)
        os_name="linux"
        ;;
    FreeBSD)
        os_name="freebsd"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        os_name="windows"
        target_dir="/c/komari-rs"
        ;;
    *)
        log_error "Unsupported operating system: $os_type"
        exit 1
        ;;
esac

# --- 参数初始化 ---
HTTP_SERVER=""
WS_SERVER=""
TOKEN=""
AUTO_DISCOVERY_KEY=""
ENDPOINT=""
CF_ACCESS_CLIENT_ID=""
CF_ACCESS_CLIENT_SECRET=""
FAKE="1"
INTERVAL="1000"
TLS_FLAG=""
IGNORE_CERT_FLAG=""
TERMINAL_FLAG=""
LOG_LEVEL="info"
IP_PROVIDER="ipinfo"
NETWORK_STATISTICS_MODE="natural"
TRAFFIC_PERIOD="month"
TRAFFIC_RESET_DAY="1"
DISABLE_TOAST_NOTIFY=""

# --- 解析命令行参数 ---
while [[ $# -gt 0 ]]; do
    case $1 in
        # 安装脚本参数
        --install-dir)
            target_dir="$2"
            shift 2
            ;;
        --install-service-name)
            service_name="$2"
            shift 2
            ;;
        --install-ghproxy)
            github_proxy="$2"
            shift 2
            ;;
        --install-version)
            install_version="$2"
            shift 2
            ;;
        # Auto Discovery 参数
        --endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        --auto-discovery-key)
            AUTO_DISCOVERY_KEY="$2"
            shift 2
            ;;
        --cf-access-client-id)
            CF_ACCESS_CLIENT_ID="$2"
            shift 2
            ;;
        --cf-access-client-secret)
            CF_ACCESS_CLIENT_SECRET="$2"
            shift 2
            ;;
        # Komari 运行参数
        --http-server)
            HTTP_SERVER="$2"
            shift 2
            ;;
        --ws-server)
            WS_SERVER="$2"
            shift 2
            ;;
        -t|--token)
            TOKEN="$2"
            shift 2
            ;;
        -f|--fake)
            FAKE="$2"
            shift 2
            ;;
        --realtime-info-interval)
            INTERVAL="$2"
            shift 2
            ;;
        --tls)
            TLS_FLAG="--tls"
            shift 1
            ;;
        --ignore-unsafe-cert)
            IGNORE_CERT_FLAG="--ignore-unsafe-cert"
            shift 1
            ;;
        --terminal)
            TERMINAL_FLAG="--terminal"
            shift 1
            ;;
        --log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --ip-provider)
            IP_PROVIDER="$2"
            shift 2
            ;;
        --network-statistics-mode)
            NETWORK_STATISTICS_MODE="$2"
            shift 2
            ;;
        --traffic-period)
            TRAFFIC_PERIOD="$2"
            shift 2
            ;;
        --traffic-reset-day)
            TRAFFIC_RESET_DAY="$2"
            shift 2
            ;;
        --disable-toast-notify)
            DISABLE_TOAST_NOTIFY="--disable-toast-notify"
            shift 1
            ;;
        --install*)
            log_warning "Unknown install parameter: $1"
            shift
            ;;
        *)
            log_warning "Unknown parameter: $1"
            shift
            ;;
    esac
done

komari_agent_path="${target_dir}/komari-monitor-rs"
auto_discovery_config="${target_dir}/auto-discovery.json"

# --- 检查 Root 权限 (Linux 特定) ---
if [ "$os_name" = "linux" ] && [ "$EUID" -ne 0 ]; then
    log_error "Please run as root on Linux systems"
    exit 1
fi

echo -e "${WHITE}===========================================${NC}"
echo -e "${WHITE}  Komari Monitor RS Installation Script   ${NC}"
echo -e "${WHITE}===========================================${NC}"
echo ""

# ============================================================================
# Auto Discovery 功能实现
# ============================================================================

# --- 加载已保存的 auto-discovery 配置 ---
load_auto_discovery_config() {
    if [ -f "$auto_discovery_config" ]; then
        log_info "Found existing auto-discovery config"
        
        # 使用 jq 或手动解析 JSON
        if command -v jq >/dev/null 2>&1; then
            SAVED_UUID=$(jq -r '.uuid' "$auto_discovery_config" 2>/dev/null)
            SAVED_TOKEN=$(jq -r '.token' "$auto_discovery_config" 2>/dev/null)
        else
            # 简单的 grep/sed 解析（不依赖 jq）
            SAVED_UUID=$(grep -o '"uuid"[[:space:]]*:[[:space:]]*"[^"]*"' "$auto_discovery_config" | sed 's/.*"\([^"]*\)".*/\1/')
            SAVED_TOKEN=$(grep -o '"token"[[:space:]]*:[[:space:]]*"[^"]*"' "$auto_discovery_config" | sed 's/.*"\([^"]*\)".*/\1/')
        fi
        
        if [ -n "$SAVED_UUID" ] && [ -n "$SAVED_TOKEN" ] && [ "$SAVED_UUID" != "null" ] && [ "$SAVED_TOKEN" != "null" ]; then
            log_success "Loaded existing UUID: ${GREEN}$SAVED_UUID${NC}"
            TOKEN="$SAVED_TOKEN"
            return 0
        else
            log_warning "Invalid auto-discovery config, will re-register"
            return 1
        fi
    fi
    return 1
}

# --- 保存 auto-discovery 配置 ---
save_auto_discovery_config() {
    local uuid="$1"
    local token="$2"
    
    cat > "$auto_discovery_config" << EOF
{
  "uuid": "$uuid",
  "token": "$token"
}
EOF
    
    chmod 600 "$auto_discovery_config"
    log_success "Auto-discovery config saved to: ${GREEN}$auto_discovery_config${NC}"
}

# --- 向服务器注册并获取 Token ---
register_with_auto_discovery() {
    local endpoint="$1"
    local key="$2"
    
    # 获取主机名
    local hostname=$(hostname)
    
    # 清理 endpoint（去掉末尾的斜杠）
    endpoint="${endpoint%/}"
    
    # 构造注册 URL
    local register_url="${endpoint}/api/clients/register?name=$(printf %s "$hostname" | jq -sRr @uri)"
    
    log_step "Registering with server..."
    log_info "Endpoint: ${CYAN}$register_url${NC}"
    log_info "Hostname: ${CYAN}$hostname${NC}"
    
    # 构造请求 JSON
    local request_json="{\"key\":\"$key\"}"
    
    # 构造 curl 命令参数
    local curl_args=(
        -X POST
        -H "Content-Type: application/json"
        -H "Authorization: Bearer $key"
        -d "$request_json"
        -s
        -w "\n%{http_code}"
    )
    
    # 添加 Cloudflare Access 头部
    if [ -n "$CF_ACCESS_CLIENT_ID" ] && [ -n "$CF_ACCESS_CLIENT_SECRET" ]; then
        curl_args+=(-H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID")
        curl_args+=(-H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET")
        log_info "Using Cloudflare Access authentication"
    fi
    
    # 发送注册请求
    local response=$(curl "${curl_args[@]}" "$register_url")
    
    # 分离响应体和状态码
    local http_code=$(echo "$response" | tail -n1)
    local response_body=$(echo "$response" | sed '$d')
    
    # 检查 HTTP 状态码
    if [ "$http_code" != "200" ]; then
        log_error "Registration failed with HTTP status: $http_code"
        log_error "Response: $response_body"
        return 1
    fi
    
    # 解析响应
    local status
    local message
    local uuid
    local token
    
    if command -v jq >/dev/null 2>&1; then
        status=$(echo "$response_body" | jq -r '.status' 2>/dev/null)
        message=$(echo "$response_body" | jq -r '.message' 2>/dev/null)
        uuid=$(echo "$response_body" | jq -r '.data.uuid' 2>/dev/null)
        token=$(echo "$response_body" | jq -r '.data.token' 2>/dev/null)
    else
        # 不依赖 jq 的简单解析
        status=$(echo "$response_body" | grep -o '"status"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)".*/\1/')
        message=$(echo "$response_body" | grep -o '"message"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)".*/\1/')
        uuid=$(echo "$response_body" | grep -o '"uuid"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)".*/\1/')
        token=$(echo "$response_body" | grep -o '"token"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)".*/\1/' | tail -n1)
    fi
    
    # 验证响应
    if [ "$status" != "success" ]; then
        log_error "Registration failed: ${message:-Unknown error}"
        log_error "Response body: $response_body"
        return 1
    fi
    
    if [ -z "$uuid" ] || [ -z "$token" ] || [ "$uuid" = "null" ] || [ "$token" = "null" ]; then
        log_error "Invalid registration response: missing UUID or token"
        log_error "Response body: $response_body"
        return 1
    fi
    
    # 保存配置
    save_auto_discovery_config "$uuid" "$token"
    
    # 设置全局 TOKEN 变量
    TOKEN="$token"
    
    log_success "Successfully registered!"
    log_success "UUID: ${GREEN}$uuid${NC}"
    log_success "Token: ${GREEN}********${NC}"
    
    return 0
}

# --- 处理 Auto Discovery 逻辑 ---
handle_auto_discovery() {
    log_step "Handling auto-discovery..."
    
    # 先尝试加载现有配置
    if load_auto_discovery_config; then
        log_info "Using existing auto-discovery token"
        return 0
    fi
    
    # 配置不存在，进行注册
    log_info "No existing config found, registering with server..."
    
    if ! register_with_auto_discovery "$ENDPOINT" "$AUTO_DISCOVERY_KEY"; then
        log_error "Auto-discovery registration failed"
        return 1
    fi
    
    return 0
}

# ============================================================================
# 配置决策逻辑
# ============================================================================

use_auto_discovery=false
if [ -n "$AUTO_DISCOVERY_KEY" ] && [ -n "$ENDPOINT" ]; then
    use_auto_discovery=true
    log_config "配置模式: ${GREEN}自动发现 (Auto Discovery)${NC}"
    log_config "  Endpoint: ${GREEN}$ENDPOINT${NC}"
    log_config "  Auto Discovery Key: ${GREEN}********${NC}"
    
    # 执行自动发现
    if ! handle_auto_discovery; then
        log_error "Auto-discovery failed, cannot continue"
        exit 1
    fi
    
    # 自动推断 HTTP/WS 服务器地址
    if [ -z "$HTTP_SERVER" ]; then
        HTTP_SERVER="$ENDPOINT"
    fi
    if [ -z "$WS_SERVER" ]; then
        # 将 http:// 替换为 ws://，https:// 替换为 wss://
        WS_SERVER=$(echo "$ENDPOINT" | sed 's|^http://|ws://|' | sed 's|^https://|wss://|')
    fi
    
elif [ -n "$HTTP_SERVER" ] && [ -n "$TOKEN" ]; then
    log_config "配置模式: ${GREEN}传统 Token${NC}"
    log_config "  HTTP Server: ${GREEN}$HTTP_SERVER${NC}"
    log_config "  WS Server: ${GREEN}${WS_SERVER:-"(自动推断)"}${NC}"
    log_config "  Token: ${GREEN}********${NC}"
    
    # 自动推断 WS 服务器
    if [ -z "$WS_SERVER" ]; then
        WS_SERVER=$(echo "$HTTP_SERVER" | sed 's|^http://|ws://|' | sed 's|^https://|wss://|')
    fi
else
    log_error "配置不完整！"
    echo ""
    echo "请选择以下配置方式之一："
    echo ""
    echo "1. 自动发现模式 (推荐):"
    echo "   bash install.sh --endpoint https://your.server.com --auto-discovery-key YOUR_KEY"
    echo ""
    echo "2. 传统 Token 模式:"
    echo "   bash install.sh --http-server http://your.server:port --token YOUR_TOKEN"
    echo ""
    exit 1
fi

log_config "安装配置:"
log_config "  Service name: ${GREEN}$service_name${NC}"
log_config "  Install directory: ${GREEN}$target_dir${NC}"
log_config "  GitHub proxy: ${GREEN}${github_proxy:-"(direct)"}${NC}"
if [ -n "$install_version" ]; then
    log_config "  Version: ${GREEN}$install_version${NC}"
else
    log_config "  Version: ${GREEN}Latest${NC}"
fi
echo ""

# --- 卸载旧版本函数 ---
uninstall_previous() {
    log_step "Checking for previous installation..."
    
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "${service_name}.service"; then
        log_info "Stopping and disabling existing systemd service..."
        systemctl stop ${service_name}.service 2>/dev/null || true
        systemctl disable ${service_name}.service 2>/dev/null || true
        rm -f "/etc/systemd/system/${service_name}.service"
        systemctl daemon-reload
    elif command -v rc-service >/dev/null 2>&1 && [ -f "/etc/init.d/${service_name}" ]; then
        log_info "Stopping and disabling existing OpenRC service..."
        rc-service ${service_name} stop 2>/dev/null || true
        rc-update del ${service_name} default 2>/dev/null || true
        rm -f "/etc/init.d/${service_name}"
    elif command -v uci >/dev/null 2>&1 && [ -f "/etc/init.d/${service_name}" ]; then
        log_info "Stopping and disabling existing procd service..."
        /etc/init.d/${service_name} stop 2>/dev/null || true
        /etc/init.d/${service_name} disable 2>/dev/null || true
        rm -f "/etc/init.d/${service_name}"
    elif command -v initctl >/dev/null 2>&1 && [ -f "/etc/init/${service_name}.conf" ]; then
        log_info "Stopping and removing existing upstart service..."
        initctl stop ${service_name} 2>/dev/null || true
        rm -f "/etc/init/${service_name}.conf"
    elif [ "$os_name" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
        system_plist="/Library/LaunchDaemons/com.komari.${service_name}.plist"
        user_plist="$HOME/Library/LaunchAgents/com.komari.${service_name}.plist"
        
        if [ -f "$system_plist" ]; then
            log_info "Stopping and removing existing system launchd service..."
            launchctl bootout system "$system_plist" 2>/dev/null || true
            rm -f "$system_plist"
        fi
        
        if [ -f "$user_plist" ]; then
            log_info "Stopping and removing existing user launchd service..."
            launchctl bootout gui/$(id -u) "$user_plist" 2>/dev/null || true
            rm -f "$user_plist"
        fi
    fi
    
    if [ -f "$komari_agent_path" ]; then
        log_info "Removing old binary..."
        rm -f "$komari_agent_path"
    fi
}

uninstall_previous

# --- 安装依赖函数 ---
install_dependencies() {
    log_step "Checking and installing dependencies..."

    local deps="curl"
    local missing_deps=""
    for cmd in $deps; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing_deps="$missing_deps $cmd"
        fi
    done

    if [ -n "$missing_deps" ]; then
        if command -v apt >/dev/null 2>&1; then
            log_info "Using apt to install dependencies..."
            apt update
            apt install -y $missing_deps
        elif command -v yum >/dev/null 2>&1; then
            log_info "Using yum to install dependencies..."
            yum install -y $missing_deps
        elif command -v apk >/dev/null 2>&1; then
            log_info "Using apk to install dependencies..."
            apk add $missing_deps
        elif command -v brew >/dev/null 2>&1; then
            log_info "Using Homebrew to install dependencies..."
            brew install $missing_deps
        else
            log_error "No supported package manager found"
            exit 1
        fi
        
        for cmd in $missing_deps; do
            if ! command -v $cmd >/dev/null 2>&1; then
                log_error "Failed to install $cmd"
                exit 1
            fi
        done
        log_success "Dependencies installed successfully"
    else
        log_success "Dependencies already satisfied"
    fi
}

install_dependencies

# --- 架构检测 ---
arch=$(uname -m)
rust_target=""
case $arch in
    x86_64)
        rust_target="x86_64-gnu"
        ;;
    aarch64|arm64)
        rust_target="aarch64-gnu"
        ;;
    i386|i686)
        rust_target="i686-gnu"
        ;;
    armv7*)
        rust_target="armv7-gnueabihf"
        ;;
    armv5tejl)
        rust_target="armv5te-gnueabi"
        ;;
    *)
        log_error "Unsupported architecture: $arch"
        exit 1
        ;;
esac

log_info "Detected OS: ${GREEN}$os_name${NC}, Architecture: ${GREEN}$arch${NC} (${rust_target})"

# --- 下载二进制 ---
version_to_install="latest"
if [ -n "$install_version" ]; then
    version_to_install="$install_version"
fi

file_name="komari-monitor-rs-${os_name}-${rust_target}"
if [ "$version_to_install" = "latest" ]; then
    download_path="download/latest"
else
    download_path="download/${version_to_install}"
fi

if [ -n "$github_proxy" ]; then
    download_url="${github_proxy}/https://github.com/${GITHUB_REPO}/releases/${download_path}/${file_name}"
else
    download_url="https://github.com/${GITHUB_REPO}/releases/${download_path}/${file_name}"
fi

log_step "Creating installation directory: ${GREEN}$target_dir${NC}"
mkdir -p "$target_dir"

log_step "Downloading ${file_name}..."
log_info "URL: ${CYAN}$download_url${NC}"

if ! curl -L -o "$komari_agent_path" "$download_url"; then
    log_error "Download failed"
    exit 1
fi

chmod +x "$komari_agent_path"
log_success "Binary installed to ${GREEN}$komari_agent_path${NC}"

# --- 构建启动命令 ---
build_exec_command() {
    local cmd="$komari_agent_path"
    
    if [ -n "$HTTP_SERVER" ]; then
        cmd="$cmd --http-server \"$HTTP_SERVER\""
    fi
    
    if [ -n "$WS_SERVER" ]; then
        cmd="$cmd --ws-server \"$WS_SERVER\""
    fi
    
    if [ -n "$TOKEN" ]; then
        cmd="$cmd --token \"$TOKEN\""
    fi
    
    # 通用参数
    cmd="$cmd --fake \"$FAKE\""
    cmd="$cmd --realtime-info-interval \"$INTERVAL\""
    cmd="$cmd --log-level \"$LOG_LEVEL\""
    cmd="$cmd --ip-provider \"$IP_PROVIDER\""
    cmd="$cmd --network-statistics-mode \"$NETWORK_STATISTICS_MODE\""
    cmd="$cmd --traffic-period \"$TRAFFIC_PERIOD\""
    cmd="$cmd --traffic-reset-day \"$TRAFFIC_RESET_DAY\""
    
    [ -n "$TLS_FLAG" ] && cmd="$cmd $TLS_FLAG"
    [ -n "$IGNORE_CERT_FLAG" ] && cmd="$cmd $IGNORE_CERT_FLAG"
    [ -n "$TERMINAL_FLAG" ] && cmd="$cmd $TERMINAL_FLAG"
    [ -n "$DISABLE_TOAST_NOTIFY" ] && cmd="$cmd $DISABLE_TOAST_NOTIFY"
    
    echo "$cmd"
}

EXEC_START_CMD=$(build_exec_command)

# --- 检测 init 系统 ---
detect_init_system() {
    if [ -f /etc/NIXOS ]; then
        echo "nixos"
        return
    fi
    
    if [ -f /etc/alpine-release ]; then
        if command -v rc-service >/dev/null 2>&1 || [ -f /sbin/openrc-run ]; then
            echo "openrc"
            return
        fi
    fi
    
    local pid1_process=$(ps -p 1 -o comm= 2>/dev/null | tr -d ' ')
    
    if [ "$pid1_process" = "systemd" ] || [ -d /run/systemd/system ]; then
        if command -v systemctl >/dev/null 2>&1; then
            if systemctl list-units >/dev/null 2>&1; then
                echo "systemd"
                return
            fi
        fi
    fi
    
    if [ "$pid1_process" = "openrc-init" ]; then
        if command -v rc-service >/dev/null 2>&1; then
            echo "openrc"
            return
        fi
    fi
    
    if command -v uci >/dev/null 2>&1 && [ -f /etc/rc.common ]; then
        echo "procd"
        return
    fi
    
    if [ "$os_name" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
        echo "launchd"
        return
    fi
    
    if command -v initctl >/dev/null 2>&1 && [ -d /etc/init ]; then
        echo "upstart"
        return
    fi
    
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-units >/dev/null 2>&1; then
            echo "systemd"
            return
        fi
    fi
    
    echo "unknown"
}

# --- 配置系统服务 ---
log_step "Configuring system service..."
init_system=$(detect_init_system)
log_info "Detected init system: ${GREEN}$init_system${NC}"

if [ "$init_system" = "nixos" ]; then
    log_warning "NixOS detected. System services must be configured declaratively."
    log_info "Please add the following to your NixOS configuration:"
    echo ""
    echo -e "${CYAN}systemd.services.${service_name} = {${NC}"
    echo -e "${CYAN}  description = \"Komari Monitor RS Service\";${NC}"
    echo -e "${CYAN}  after = [ \"network.target\" ];${NC}"
    echo -e "${CYAN}  wantedBy = [ \"multi-user.target\" ];${NC}"
    echo -e "${CYAN}  serviceConfig = {${NC}"
    echo -e "${CYAN}    Type = \"simple\";${NC}"
    echo -e "${CYAN}    ExecStart = \"${EXEC_START_CMD}\";${NC}"
    echo -e "${CYAN}    WorkingDirectory = \"${target_dir}\";${NC}"
    echo -e "${CYAN}    Restart = \"always\";${NC}"
    echo -e "${CYAN}    RestartSec = \"5\";${NC}"
    echo -e "${CYAN}    User = \"root\";${NC}"
    echo -e "${CYAN}  };${NC}"
    echo -e "${CYAN}};${NC}"
    echo ""
elif [ "$init_system" = "openrc" ]; then
    log_info "Using OpenRC for service management"
    service_file="/etc/init.d/${service_name}"
    cat > "$service_file" << EOF
#!/sbin/openrc-run

name="Komari Monitor RS Service"
description="Komari monitoring agent (Rust version)"
command="${komari_agent_path}"
command_args="$(echo "$EXEC_START_CMD" | sed "s|$komari_agent_path ||")"
command_user="root"
directory="${target_dir}"
pidfile="/run/${service_name}.pid"
retry="SIGTERM/30"
supervisor=supervise-daemon

depend() {
    need net
    after network
}
EOF
    chmod +x "$service_file"
    rc-update add ${service_name} default
    rc-service ${service_name} start
    log_success "OpenRC service configured and started"
    
elif [ "$init_system" = "systemd" ]; then
    log_info "Using systemd for service management"
    service_file="/etc/systemd/system/${service_name}.service"
    cat > "$service_file" << EOF
[Unit]
Description=Komari Monitor RS Service
After=network.target

[Service]
Type=simple
ExecStart=${EXEC_START_CMD}
WorkingDirectory=${target_dir}
Restart=always
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ${service_name}.service
    systemctl start ${service_name}.service
    log_success "Systemd service configured and started"
    
elif [ "$init_system" = "procd" ]; then
    log_info "Using procd for service management"
    service_file="/etc/init.d/${service_name}"
    cat > "$service_file" << EOF
#!/bin/sh /etc/rc.common

START=99
STOP=10

USE_PROCD=1

PROG="${komari_agent_path}"
ARGS="$(echo "$EXEC_START_CMD" | sed "s|$komari_agent_path ||")"

start_service() {
    procd_open_instance
    procd_set_param command \$PROG \$ARGS
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param user root
    procd_close_instance
}

stop_service() {
    killall \$(basename \$PROG)
}
EOF
    chmod +x "$service_file"
    /etc/init.d/${service_name} enable
    /etc/init.d/${service_name} start
    log_success "procd service configured and started"
    
elif [ "$init_system" = "launchd" ]; then
    log_info "Using launchd for service management"
    
    if [[ "$target_dir" =~ ^/Users/.* ]] || [ "$EUID" -ne 0 ]; then
        plist_dir="$HOME/Library/LaunchAgents"
        plist_file="$plist_dir/com.komari.${service_name}.plist"
        service_user="$(whoami)"
        log_dir="$HOME/Library/Logs"
    else
        plist_dir="/Library/LaunchDaemons"
        plist_file="$plist_dir/com.komari.${service_name}.plist"
        service_user="root"
        log_dir="/var/log"
    fi
    
    mkdir -p "$plist_dir"
    
    cat > "$plist_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.komari.${service_name}</string>
    <key>ProgramArguments</key>
    <array>
EOF
    
    echo "$EXEC_START_CMD" | xargs -n1 | while read arg; do
        echo "        <string>$(echo "$arg" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')</string>" >> "$plist_file"
    done
    
    cat >> "$plist_file" << EOF
    </array>
    <key>WorkingDirectory</key>
    <string>${target_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>${service_user}</string>
    <key>StandardOutPath</key>
    <string>${log_dir}/${service_name}.log</string>
    <key>StandardErrorPath</key>
    <string>${log_dir}/${service_name}.log</string>
</dict>
</plist>
EOF
    
    if [[ "$target_dir" =~ ^/Users/.* ]] || [ "$EUID" -ne 0 ]; then
        launchctl bootstrap gui/$(id -u) "$plist_file"
    else
        launchctl bootstrap system "$plist_file"
    fi
    log_success "launchd service configured and started"
    
elif [ "$init_system" = "upstart" ]; then
    log_info "Using upstart for service management"
    service_file="/etc/init/${service_name}.conf"
    cat > "$service_file" << EOF
description "Komari Monitor RS Service"

chdir ${target_dir}
start on filesystem or runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 5

script
    exec ${EXEC_START_CMD}
end script
EOF
    initctl reload-configuration
    initctl start ${service_name}
    log_success "Upstart service configured and started"
else
    log_error "Unsupported or unknown init system: $init_system"
    exit 1
fi

echo ""
echo -e "${WHITE}===========================================${NC}"
log_success "Komari Monitor RS installation completed!"
echo ""
log_config "Installation Summary:"
log_config "  Mode: ${GREEN}$([ "$use_auto_discovery" = true ] && echo "Auto Discovery" || echo "Token")${NC}"
log_config "  Service: ${GREEN}$service_name${NC}"
log_config "  Binary: ${GREEN}$komari_agent_path${NC}"
if [ "$use_auto_discovery" = true ]; then
    log_config "  Config: ${GREEN}$auto_discovery_config${NC}"
fi
log_config "  HTTP Server: ${GREEN}$HTTP_SERVER${NC}"
log_config "  WS Server: ${GREEN}$WS_SERVER${NC}"
log_config "  Network Mode: ${GREEN}$NETWORK_STATISTICS_MODE${NC} (${TRAFFIC_PERIOD}, reset on day ${TRAFFIC_RESET_DAY})"
echo ""
log_info "Useful commands:"
if [ "$init_system" = "systemd" ]; then
    echo "  - Check status: ${CYAN}systemctl status ${service_name}${NC}"
    echo "  - View logs: ${CYAN}journalctl -u ${service_name} -f${NC}"
    echo "  - Restart: ${CYAN}systemctl restart ${service_name}${NC}"
    echo "  - Stop: ${CYAN}systemctl stop ${service_name}${NC}"
elif [ "$init_system" = "openrc" ]; then
    echo "  - Check status: ${CYAN}rc-service ${service_name} status${NC}"
    echo "  - View logs: ${CYAN}tail -f /var/log/${service_name}.log${NC}"
    echo "  - Restart: ${CYAN}rc-service ${service_name} restart${NC}"
    echo "  - Stop: ${CYAN}rc-service ${service_name} stop${NC}"
elif [ "$init_system" = "procd" ]; then
    echo "  - Check status: ${CYAN}/etc/init.d/${service_name} status${NC}"
    echo "  - View logs: ${CYAN}logread -f${NC}"
    echo "  - Restart: ${CYAN}/etc/init.d/${service_name} restart${NC}"
    echo "  - Stop: ${CYAN}/etc/init.d/${service_name} stop${NC}"
elif [ "$init_system" = "launchd" ]; then
    echo "  - View logs: ${CYAN}tail -f ${log_dir}/${service_name}.log${NC}"
    echo "  - Restart: ${CYAN}launchctl kickstart -k system/com.komari.${service_name}${NC}"
elif [ "$init_system" = "upstart" ]; then
    echo "  - Check status: ${CYAN}initctl status ${service_name}${NC}"
    echo "  - Restart: ${CYAN}initctl restart ${service_name}${NC}"
    echo "  - Stop: ${CYAN}initctl stop ${service_name}${NC}"
fi

if [ "$use_auto_discovery" = true ]; then
    echo ""
    log_info "Auto-discovery config is saved at: ${CYAN}$auto_discovery_config${NC}"
    log_info "Token will be automatically reused on reinstall"
fi

echo -e "${WHITE}===========================================${NC}"