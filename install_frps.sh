#!/bin/bash
set -euo pipefail

########################### 基础变量 (使用系统路径) ###################################
BASE_DIR="$PWD" # 保留当前目录，用于客户端模板和非系统文件
BIN_PATH="/usr/local/bin/frps" # 可执行文件
CONF_DIR="/etc/frp" # 配置目录
CONF_PATH="$CONF_DIR/frps.toml" # 配置文件
LOG_FILE="/var/log/frps.log" # 系统日志文件 (用于 frps.toml)
CLIENT_TMPL="$BASE_DIR/frpc.toml" # 客户端模板
########################### 工具函数 ###################################
log() { echo "[INFO] $*"; }
warn(){ echo "[WARN] $*" >&2; }
err() { echo "[ERROR] $*" >&2; exit 1;}
check_root(){ [[ $EUID -eq 0 ]] || err "请使用 root 运行"; }
command_exists(){ command -v "$1" >/dev/null 2>&1; }
install_deps(){
    if command -v apt >/dev/null 2>&1; then
        apt update -y && apt install -y wget tar curl openssl jq
    elif command -v yum >/dev/null 2>&1; then
        yum install -y wget tar curl openssl jq
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y wget tar curl openssl jq
    else
        err "未识别的包管理器，请手动安装 wget tar curl openssl jq"
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
########################### Cloudflare API ##############################
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
    # 检查现有记录
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
        if [[ "$current_content" == "$server_ip" && "$current_proxied" == "false" ]]; then
            log "DNS 记录已存在且匹配，无需更改"
            return 0
        else
            # 更新记录
            local resp=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
                -H "Authorization: Bearer $CF_API_TOKEN" \
                -H "Content-Type: application/json" \
                --data "{
                    \"type\":\"A\",
                    \"name\":\"$subdomain\",
                    \"content\":\"$server_ip\",
                    \"ttl\":120,
                    \"proxied\":false
                }")
            if echo "$resp" | jq -e '.success' >/dev/null; then
                log "DNS 记录已更新（DNS only 模式）"
                return 0
            else
                warn "API 更新失败：$(echo "$resp" | jq -r '.errors[0].message')"
                return 1
            fi
        fi
    else
        # 添加新记录
        local resp=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data "{
                \"type\":\"A\",
                \"name\":\"$subdomain\",
                \"content\":\"$server_ip\",
                \"ttl\":120,
                \"proxied\":false
            }")
        if echo "$resp" | jq -e '.success' >/dev/null; then
            log "DNS 记录已自动添加（DNS only 模式）"
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

# --- 核心修复：frps安装/更新，使用系统路径和绝对日志路径 ---
install_frps(){
    log "开始安装/更新 frps ..."
    [[ $EUID -eq 0 ]] || err "请使用 root 运行"
    install_deps
    VER=${1:-$(get_latest_ver)}
    [ -z "$VER" ] && VER="0.66.0"
    ARCH=$(get_arch)
    URL="https://github.com/fatedier/frp/releases/download/v${VER}/frp_${VER}_linux_${ARCH}.tar.gz"

    # 检查版本和安装可执行文件到 /usr/local/bin
    if [[ -x $BIN_PATH ]] && $BIN_PATH --version 2>&1 | grep -q "$VER"; then
        log "frps v$VER 已安装，跳过下载"
    else
        log "下载 frp v$VER ..."
        wget -qO- "$URL" | tar -xz --strip-components=1 -C /tmp
        install -Dm755 /tmp/frps "$BIN_PATH" # 安装到 /usr/local/bin
        rm -rf /tmp/frp*
    fi

    # 配置目录和配置文件到 /etc/frp
    mkdir -p "$CONF_DIR"
    # 确保日志文件路径可写（通常 /var/log 可写）
    touch "$LOG_FILE"
    
    if [[ ! -f $CONF_PATH ]]; then
        TOKEN=$(openssl rand -hex 16)
        # 生成「模板化」配置，日志路径改为绝对路径
        cat > "$CONF_PATH" <<EOF
bindPort = 7000
auth.token = "__TOKEN_PLACEHOLDER__"
vhostHTTPSPort = 8443
[log]
to = "$LOG_FILE" # <--- 核心修复：使用绝对路径 /var/log/frps.log
level = "info"
[[proxies]]
name = "auth-https"
type = https
localIP = "localhost"
localPort = 8080
customDomains = ["__DOMAIN_PLACEHOLDER__"]
EOF
        # 把真实 token 替换占位符
        sed -i "s/__TOKEN_PLACEHOLDER__/$TOKEN/g" "$CONF_PATH"
        log "已生成「模板化」配置文件，Token：$TOKEN"
    else
        TOKEN=$(awk -F'"' '/auth.token/ {print $2}' "$CONF_PATH" 2>/dev/null || openssl rand -hex 16)
        log "使用已有配置，Token：$TOKEN"
    fi

    # systemd 单元（工作目录指向配置目录 /etc/frp）
    [[ -f /etc/systemd/system/frps.service ]] && systemctl disable --now frps.service 2>/dev/null
    cat > /etc/systemd/system/frps.service <<EOF
[Unit]
Description=frp Server
After=network.target
[Service]
Type=simple
# 核心修复：工作目录设置为配置目录，但日志已是绝对路径，更健壮
WorkingDirectory=$CONF_DIR 
# ExecStart 使用绝对路径
ExecStart=$BIN_PATH -c $CONF_PATH
Restart=always
RestartSec=5
# 推荐：服务运行用户降权，但为保持与原脚本一致性，此处暂不设置 User=nobody
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
    CURRENT_PORT=$(awk -F'=' '/vhostHTTPSPort/ {gsub(/ /,"",$2); print $2}' "$CONF_PATH" 2>/dev/null || echo "8443")
    read -rp "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        warn "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。"
        read -rp "按回车返回菜单..."
        return
    fi
    # 使用 ss 检查端口占用
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        warn "端口 $NEW_PORT 已被占用，请更换或先停用占用服务"
        read -rp "按回车返回菜单..."
        return
    fi
    sed -i "s/^vhostHTTPSPort.*/vhostHTTPSPort = $NEW_PORT/" "$CONF_PATH"
    sed -i "s|customDomains = \[[^]]*\]|customDomains = [\"$DOMAIN\"]|" "$CONF_PATH" 2>/dev/null || true
    systemctl restart frps
    log "域名已设为 $DOMAIN，端口已设为 $NEW_PORT"
    log "请手动到 Cloudflare 控制台添加 A 记录（DNS only, 灰色云，不要开启代理）"
    read -rp "按回车返回菜单..."
}
auto_domain(){
    read -rp "请输入完整子域名 (如 auth.example.com): " DOMAIN
    [[ -z $DOMAIN ]] && { warn "域名为空，返回菜单"; return; }
    if [[ -z "${CF_API_TOKEN:-}" ]]; then
        read -rp "请输入 Cloudflare API Token（需 Zone:DNS:Edit 权限）: " CF_API_TOKEN
    fi
    read -rp "请输入 Cloudflare Zone ID（可选，按回车自动获取）: " ZONE_ID
    CURRENT_PORT=$(awk -F'=' '/vhostHTTPSPort/ {gsub(/ /,"",$2); print $2}' "$CONF_PATH" 2>/dev/null || echo "8443")
    read -rp "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        warn "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。"
        read -rp "按回车返回菜单..."
        return
    fi
    # 使用 ss 检查端口占用
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        warn "端口 $NEW_PORT 已被占用，请更换或先停用占用服务"
        read -rp "按回车返回菜单..."
        return
    fi
    # 先写入配置
    sed -i "s/^vhostHTTPSPort.*/vhostHTTPSPort = $NEW_PORT/" "$CONF_PATH"
    sed -i "s|customDomains = \[[^]]*\]|customDomains = [\"$DOMAIN\"]|" "$CONF_PATH" 2>/dev/null || true
    # 尝试自动添加 DNS
    if cf_add_dns "$DOMAIN"; then
        log "配置已生效"
    else
        warn "自动添加失败，已回退为「仅写入配置」"
        log "请手动到 Cloudflare 控制台添加 A 记录（DNS only, 灰色云，不要开启代理）"
    fi
    systemctl restart frps
    read -rp "按回车返回菜单..."
}
gen_tmpl(){
    SERVER_IP=$(curl -s ifconfig.me)
    DOMAIN=$(awk -F'"' '/customDomains/ {print $2}' "$CONF_PATH" 2>/dev/null || echo "auth.yourdomain.com")
    cat > "$CLIENT_TMPL" <<EOF
# 客户端模板（复制到内网机器使用）
serverAddr = "$SERVER_IP"
serverPort = 7000
auth.token = $(awk -F'"' '/auth.token/ {print $2}' "$CONF_PATH")
[[proxies]]
name = "auth-https"
type = https
localIP = "127.0.0.1"
localPort = 8080
customDomains = ["$DOMAIN"]
EOF
    log "模板已保存：$CLIENT_TMPL (位于当前目录)"
    read -rp "按回车返回菜单..."
}
show_status(){
    systemctl is-active frps && log "frps 正在运行" || warn "frps 未运行"
    echo "Token: $(awk -F'"' '/auth.token/ {print $2}' "$CONF_PATH" 2>/dev/null || echo '未找到')"
    local domain=$(awk -F'"' '/customDomains/ {print $2}' "$CONF_PATH" 2>/dev/null)
    local port=$(awk -F'=' '/vhostHTTPSPort/ {gsub(/ /,"",$2); print $2}' "$CONF_PATH" 2>/dev/null || echo "8443")
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
    rm -rf "$CONF_DIR" # /etc/frp 及其内容
    rm -f "$LOG_FILE" # /var/log/frps.log
    systemctl daemon-reload
    log "frps 已卸载"
    read -rp "按回车返回菜单..."
}
########################### 入口 #####################################
menu_main
