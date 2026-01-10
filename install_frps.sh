#!/bin/bash
set -euo pipefail

########################### 基础变量 (使用系统路径) ###################################
BASE_DIR="$PWD" # 保留当前目录，仅用于客户端模板和非系统文件，不用于服务配置
BIN_PATH="/usr/local/bin/frps" # 可执行文件安装路径
CONF_DIR="/etc/frp" # 配置目录安装路径
CONF_PATH="$CONF_DIR/frps.ini" # 配置文件路径统一改为 .ini
LOG_FILE="/var/log/frps.log" # 系统日志文件
CLIENT_TMPL="$BASE_DIR/frpc.toml" # 客户端模板
########################### 工具函数 ###################################
log() { echo "[INFO] $*"; }
warn(){ echo "[WARN] $*" >&2; }
err() { echo "[ERROR] $*" >&2; exit 1;}
check_root(){ [[ $EUID -eq 0 ]] || err "请使用 root 运行"; }
command_exists(){ command -v "$1" >/dev/null 2>&1; }
install_deps(){
    if command -v apt >/dev/null 2>&1; then
        apt update -y && apt install -y wget tar curl openssl jq dos2unix
    elif command -v yum >/dev/null 2>&1; then
        yum install -y wget tar curl openssl jq dos2unix
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y wget tar curl openssl jq dos2unix
    else
        err "未识别的包管理器，请手动安装 wget tar curl openssl jq dos2unix"
    fi
}
get_latest_ver(){
    curl -s https://api.github.com/repos/fatedier/frp/releases/latest |
    grep -oP '"tag_name": "\Kv[^"]+' | sed 's/^v//'
}
get_arch(){
    case $(uname -m) in
        x86_64) echo amd64 ;;
        aarch64)echo arm64 ;;
        *) err "不支持的架构: $(uname -m)" ;;
    esac
}
########################### Cloudflare API (增强 Zone ID 查找) ##############################
# 新增函数：通过子域名自动查找 Zone ID
find_zone_id(){
    local subdomain=$1
    local parts=(${subdomain//\./ })
    local len=${#parts[@]}
    
    for ((i=$len; i>=2; i--)); do
        local try_domain=$(IFS='.'; echo "${parts[*]: -i}")
        local zone_id=$(curl -s -H "Authorization: Bearer $CF_API_TOKEN" \
            "https://api.cloudflare.com/client/v4/zones?name=$try_domain" | jq -r '.result[0].id // empty')
        
        if [[ -n $zone_id ]]; then
            echo "$zone_id"
            return 0
        fi
    done
    return 1
}

cf_add_dns(){
    local subdomain=$1
    local server_ip=$(curl -s ifconfig.me)
    local zone_id

    if [[ -n "${ZONE_ID:-}" ]]; then
        zone_id=$ZONE_ID
    else
        zone_id=$(find_zone_id "$subdomain") 
        [[ -z $zone_id ]] && { warn "未找到合适的 Zone，回退手动添加"; return 1; }
    fi

    local record_name="${subdomain%.*}" 
    
    local get_resp=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=A&name=$subdomain" \
        -H "Authorization: Bearer $CF_API_TOKEN")
    local num_results=$(echo "$get_resp" | jq '.result | length')

    if [[ $num_results -gt 1 ]]; then
        warn "存在多个 A 记录，请手动管理"
        return 1
    elif [[ $num_results -eq 1 ]]; then
        local record_id=$(echo "$get_resp" | jq -r '.result[0].id')
        local current_content=$(echo "$get_resp" | jq -r '.result[0].content')
        local current_proxied=$(echo "$get_resp" | jq -r '.result[0].proxied')
        
        if [[ "$current_content" == "$server_ip" && "$current_proxied" == "true" ]]; then
            log "DNS 记录已存在且匹配 (橙色云)，无需更改"
            return 0
        else
            local resp=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
                -H "Authorization: Bearer $CF_API_TOKEN" \
                -H "Content-Type: application/json" \
                --data "{
                    \"type\":\"A\",
                    \"name\":\"$subdomain\",
                    \"content\":\"$server_ip\",
                    \"ttl\":120,
                    \"proxied\":true
                }")
            if echo "$resp" | jq -e '.success' >/dev/null; then
                log "DNS 记录已更新（橙色云模式）"
                return 0
            else
                warn "API 更新失败：$(echo "$resp" | jq -r '.errors[0].message')"
                return 1
            fi
        fi
    else
        local resp=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{
                \"type\":\"A\",
                \"name\":\"$record_name\",
                \"content\":\"$server_ip\",
                \"ttl\":120,
                \"proxied\":true
            }")
        if echo "$resp" | jq -e '.success' >/dev/null; then
            log "DNS 记录已自动添加并开启代理（橙色云）"
            return 0
        else
            warn "API 调用失败：$(echo "$resp" | jq -r '.errors[0].message')"
            return 1
        fi
    fi
}
########################### 业务函数 ###################################
menu_main(){
    while true; do
        echo
        echo "======== frp 一键管理菜单 ========"
        echo "1) 安装/更新 frps"
        echo "2) 设置域名"
        echo "3) 生成客户端模板"
        echo "4) 查看运行状态"
        echo "5) 卸载 frps"
        echo "6) 重启 frps"
        echo "7) 终止 frps"
        echo "0) 退出"
        echo "=================================="
        read -rp "请选择操作 [0-7]: " choice
        case $choice in
            1) install_frps ;;
            2) set_domain ;;
            3) gen_tmpl ;;
            4) show_status ;;
            5) uninstall ;;
            6) restart_frps ;;
            7) stop_frps ;;
            0) log "再见！"; exit 0 ;;
            *) warn "无效选择，请重试";;
        esac
    done
}
# --- 重启 frps ---
restart_frps(){
    log "正在重启 frps..."
    if systemctl is-active frps >/dev/null 2>&1; then
        systemctl restart frps
        log "frps 已重启"
    else
        warn "frps 未运行，将尝试启动..."
        systemctl start frps
        if systemctl is-active frps >/dev/null 2>&1; then
            log "frps 已启动"
        else
            err "frps 启动失败，请检查日志 journalctl -u frps"
        fi
    fi
    read -rp "按回车返回菜单..."
}
# --- 终止 frps ---
stop_frps(){
    log "正在终止 frps..."
    if systemctl is-active frps >/dev/null 2>&1; then
        systemctl stop frps
        log "frps 已终止"
    else
        warn "frps 未运行，无需终止"
    fi
    read -rp "按回车返回菜单..."
}

# --- 核心修复：frps安装/更新，使用 .ini 格式 ---
install_frps(){
    log "开始安装/更新 frps ..."
    [[ $EUID -eq 0 ]] || err "请使用 root 运行"
    install_deps
    VER=${1:-$(get_latest_ver)}
    [ -z "$VER" ] && VER="0.66.0"
    ARCH=$(get_arch)
    URL="https://github.com/fatedier/frp/releases/download/v${VER}/frp_${VER}_linux_${ARCH}.tar.gz"

    if [[ -x $BIN_PATH ]] && $BIN_PATH --version 2>&1 | grep -q "$VER"; then
        log "frps v$VER 已安装，跳过下载"
    else
        log "下载 frp v$VER ..."
        wget -qO- "$URL" | tar -xz --strip-components=1 -C /tmp
        install -Dm755 /tmp/frps "$BIN_PATH"
        rm -rf /tmp/frp*
    fi

    mkdir -p "$CONF_DIR"
    touch "$LOG_FILE"
    
    if [[ ! -f $CONF_PATH ]]; then
        TOKEN=$(openssl rand -hex 16)
        # 生成 .ini 格式配置模板
        cat > "$CONF_PATH" <<EOF
[common]
bind_port = 7000
token = "__TOKEN_PLACEHOLDER__"
vhost_https_port = 8443
log_file = "$LOG_FILE" # <--- INI 格式兼容
log_level = info

[auth-https]
type = https
local_ip = 127.0.0.1
local_port = 8080
custom_domains = __DOMAIN_PLACEHOLDER__
EOF
        # 将 TOML 字段替换为 INI 字段 (虽然内容是 INI，但 TOML/INI 字段有差异)
        sed -i "s/__TOKEN_PLACEHOLDER__/$TOKEN/g" "$CONF_PATH"
        # TOML 数组格式替换为 INI 兼容格式 (无需引号，直接替换)
        sed -i "s/customDomains = \[\"[^]]*\"\]/custom_domains = __DOMAIN_PLACEHOLDER__/" "$CONF_PATH" 2>/dev/null || true

        log "已生成「模板化」配置文件 ($CONF_PATH)，Token：$TOKEN"
    else
        # 尝试从 INI/TOML 格式中提取 Token
        TOKEN=$(grep -E '^(token|auth\.token)' "$CONF_PATH" | awk -F'= ' '{print $2}' | tr -d '"' | head -n 1 2>/dev/null || openssl rand -hex 16)
        log "使用已有配置 ($CONF_PATH)，Token：$TOKEN"
    fi

    # systemd 单元（工作目录指向配置目录 /etc/frp）
    [[ -f /etc/systemd/system/frps.service ]] && systemctl disable --now frps.service 2>/dev/null
    cat > /etc/systemd/system/frps.service <<EOF
[Unit]
Description=frp Server
After=network.target
[Service]
Type=simple
WorkingDirectory=$CONF_DIR 
ExecStart=$BIN_PATH -c $CONF_PATH
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now frps.service
    log "frps 已启动并设为开机自启"
    read -rp "按回车返回菜单..."
}

set_domain(){
    log "---- 设置域名 ----"
    echo "1) 仅写入配置（手动去 Cloudflare 添加 DNS）"
    echo "2) 自动添加 DNS 并写入配置（需要 Cloudflare API Token）"
    read -rp "请选择 [1-2]: " MODE
    case $MODE in
        1) manual_domain ;;
        2) auto_domain ;;
        *) warn "无效选择"; return ;;
    esac
}
manual_domain(){
    read -rp "请输入完整子域名 (如 auth.example.com): " DOMAIN
    [[ -z $DOMAIN ]] && { warn "域名为空，返回菜单"; return; }
    
    # 兼容 INI 和 TOML/TOML-like 格式的端口提取
    CURRENT_PORT=$(grep -E '^(vhost_https_port|vhostHTTPSPort)' "$CONF_PATH" | awk -F'[ =]' '{print $NF}' | head -n 1 2>/dev/null || echo "8443")
    read -rp "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}

    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        warn "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。"
        read -rp "按回车返回菜单..."
        return
    fi
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        warn "端口 $NEW_PORT 已被占用，请更换或先停用占用服务"
        read -rp "按回车返回菜单..."
        return
    fi
    
    # 修复：同时替换 INI 格式字段和端口值
    sed -i "s/^\(vhost_https_port\|vhostHTTPSPort\).*/vhost_https_port = $NEW_PORT/" "$CONF_PATH"
    # 修复：替换 INI 格式的 custom_domains 字段
    sed -i "s/custom_domains = .*/custom_domains = $DOMAIN/" "$CONF_PATH" 2>/dev/null || true
    
    systemctl restart frps
    log "域名已设为 $DOMAIN，端口已设为 $NEW_PORT"
    log "请手动到 Cloudflare 控制台添加 A 记录并开启橙色云"
    read -rp "按回车返回菜单..."
}
auto_domain(){
    read -rp "请输入完整子域名 (如 auth.example.com): " DOMAIN
    [[ -z $DOMAIN ]] && { warn "域名为空，返回菜单"; return; }
    if [[ -z "${CF_API_TOKEN:-}" ]]; then
        read -rp "请输入 Cloudflare API Token（需 Zone:DNS:Edit 权限）: " CF_API_TOKEN
    fi
    read -rp "请输入 Cloudflare Zone ID（可选，按回车自动获取）: " ZONE_ID
    
    CURRENT_PORT=$(grep -E '^(vhost_https_port|vhostHTTPSPort)' "$CONF_PATH" | awk -F'[ =]' '{print $NF}' | head -n 1 2>/dev/null || echo "8443")
    read -rp "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        warn "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。"
        read -rp "按回车返回菜单..."
        return
    fi
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        warn "端口 $NEW_PORT 已被占用，请更换或先停用占用服务"
        read -rp "按回车返回菜单..."
        return
    fi
    
    # 先写入配置 (INI 格式)
    sed -i "s/^\(vhost_https_port\|vhostHTTPSPort\).*/vhost_https_port = $NEW_PORT/" "$CONF_PATH"
    sed -i "s/custom_domains = .*/custom_domains = $DOMAIN/" "$CONF_PATH" 2>/dev/null || true

    if cf_add_dns "$DOMAIN"; then
        log "配置已生效"
    else
        warn "自动添加失败，已回退为「仅写入配置」"
        log "请手动到 Cloudflare 控制台添加 A 记录并开启橙色云"
    fi
    systemctl restart frps
    read -rp "按回车返回菜单..."
}
gen_tmpl(){
    SERVER_IP=$(curl -s ifconfig.me)
    # 修复：从 INI/TOML 配置中提取域名和 Token
    DOMAIN=$(grep 'custom_domains' "$CONF_PATH" | awk -F'= ' '{print $2}' | tr -d '"' | head -n 1 2>/dev/null || echo "auth.yourdomain.com")
    TOKEN=$(grep -E '^(token|auth\.token)' "$CONF_PATH" | awk -F'= ' '{print $2}' | tr -d '"' | head -n 1 2>/dev/null)
    
    cat > "$CLIENT_TMPL" <<EOF
# 客户端模板（复制到内网机器使用）
[common]
server_addr = $SERVER_IP
server_port = 7000
token = $TOKEN

[auth-https]
type = https
local_ip = 127.0.0.1
local_port = 8080
custom_domains = $DOMAIN
EOF
    log "模板已保存：$CLIENT_TMPL (位于当前目录)"
    read -rp "按回车返回菜单..."
}
show_status(){
    systemctl is-active frps && log "frps 正在运行" || warn "frps 未运行"
    # 修复：从 INI/TOML 配置中提取 Token
    TOKEN=$(grep -E '^(token|auth\.token)' "$CONF_PATH" | awk -F'= ' '{print $2}' | tr -d '"' | head -n 1 2>/dev/null || echo '未找到')
    echo "Token: $TOKEN"
    
    # 修复：从 INI/TOML 配置中提取域名和端口
    local domain=$(grep 'custom_domains' "$CONF_PATH" | awk -F'= ' '{print $2}' | tr -d '"' | head -n 1 2>/dev/null)
    local port=$(grep -E '^(vhost_https_port|vhostHTTPSPort)' "$CONF_PATH" | awk -F'[ =]' '{print $NF}' | head -n 1 2>/dev/null || echo "8443")
    
    local access="https://$(curl -s ifconfig.me):$port"
    if [[ -n $domain ]]; then
        if [[ $port == 443 ]]; then
            access="https://$domain"
        else
            access="https://$domain:$port"
        fi
    fi
    echo "访问地址: $access"
    echo "日志位置: $LOG_FILE"
    read -rp "按回车返回菜单..."
}
# --- 卸载函数，清理系统路径 ---
uninstall(){
    warn "即将卸载 frps 并删除配置与日志"
    read -rp "确认继续？(y/N): " sure
    [[ $sure =~ ^[Yy]$ ]] || return
    systemctl stop frps.service 2>/dev/null
    systemctl disable frps.service 2>/dev/null
    rm -f /etc/systemd/system/frps.service
    rm -f "$BIN_PATH" # /usr/local/bin/frps
    rm -rf "$CONF_DIR" # /etc/frp 及其内容 (包括 frps.ini)
    rm -f "$LOG_FILE" # /var/log/frps.log
    systemctl daemon-reload
    log "frps 已卸载"
    read -rp "按回车返回菜单..."
}
########################### 入口 #####################################
menu_main
