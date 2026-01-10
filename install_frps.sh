#!/bin/bash
set -euo pipefail
########################### 基础变量 ###################################
BASE_DIR="$PWD" # 以执行目录为根
BIN_PATH="$BASE_DIR/frps" # 可执行文件
CONF_PATH="$BASE_DIR/frps.toml" # 配置
LOG_FILE="$BASE_DIR/frps.log" # 日志
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
cf_add_dns(){
    local subdomain=$1
    local domain=${subdomain#*.} # 主域名
    local record_name=$subdomain # 对于 Cloudflare API，name 是完整子域名，如 frp.omail.us.kg
    local server_ip=$(curl -s ifconfig.me)
    # 获取 Zone ID
    local zone_id=$(curl -s -H "Authorization: Bearer $CF_API_TOKEN" \
        "https://api.cloudflare.com/client/v4/zones?name=$domain" | jq -r '.result[0].id // empty')
    [[ -z $zone_id ]] && { warn "未找到 Zone，回退手动添加"; return 1; }
    # 检查现有记录
    local existing_record=$(curl -s -H "Authorization: Bearer $CF_API_TOKEN" \
        "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=A&name=$record_name" | jq -r '.result[0] // empty')
    if [[ -n "$existing_record" ]]; then
        local record_id=$(echo "$existing_record" | jq -r '.id')
        local current_content=$(echo "$existing_record" | jq -r '.content')
        local current_proxied=$(echo "$existing_record" | jq -r '.proxied')
        if [[ "$current_content" == "$server_ip" && "$current_proxied" == "true" ]]; then
            log "DNS 记录已存在且配置正确，无需修改"
            return 0
        else
            # 更新记录
            local resp=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
                -H "Authorization: Bearer $CF_API_TOKEN" \
                -H "Content-Type: application/json" \
                --data "{
                    \"content\":\"$server_ip\",
                    \"ttl\":120,
                    \"proxied\":true
                }")
            if echo "$resp" | jq -e '.success' >/dev/null; then
                log "DNS 记录已更新并开启代理"
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
                \"name\":\"$record_name\",
                \"content\":\"$server_ip\",
                \"ttl\":120,
                \"proxied\":true
            }")
        if echo "$resp" | jq -e '.success' >/dev/null; then
            log "DNS 记录已自动添加并开启代理"
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
# --- 新增函数：重启 frps ---
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
            err "frps 启动失败，请检查日志 $LOG_FILE"
        fi
    fi
    read -rp "按回车返回菜单..."
}
# --- 新增函数：终止 frps ---
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
    mkdir -p "$(dirname "$CONF_PATH")"
    if [[ ! -f $CONF_PATH ]]; then
        TOKEN=$(openssl rand -hex 16)
        # 先生成「模板化」配置（占位符）
        cat > "$CONF_PATH" <<'EOF'
bindPort = 7000
auth.token = "__TOKEN_PLACEHOLDER__"
vhostHTTPSPort = 8443
[log]
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
        TOKEN=$(awk -F'"' '/auth.token/ {print $2}' "$CONF_PATH")
        log "使用已有配置，Token：$TOKEN"
    fi
    # systemd 单元（工作目录指向当前目录）
    [[ -f /etc/systemd/system/frps.service ]] && systemctl disable --now frps.service 2>/dev/null
    cat > /etc/systemd/system/frps.service <<EOF
[Unit]
Description=frp Server
After=network.target
[Service]
Type=simple
WorkingDirectory=$BASE_DIR
ExecStartPre=/usr/bin/touch $LOG_FILE
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
    CURRENT_PORT=$(awk -F'=' '/vhostHTTPSPort/ {gsub(/ /,"",$2); print $2}' "$CONF_PATH" 2>/dev/null || echo "8443")
    read -rp "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    # === 端口校验逻辑（新增/修复）
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        warn "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。"
        read -rp "按回车返回菜单..."
        return
    fi
    # ===
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        warn "端口 $NEW_PORT 已被占用，请更换或先停用占用服务"
        read -rp "按回车返回菜单..."
        return
    fi
    sed -i "s/^vhostHTTPSPort.*/vhostHTTPSPort = $NEW_PORT/" "$CONF_PATH"
    sed -i "s|customDomains = \[[^]]*\]|customDomains = [\"$DOMAIN\"]|" "$CONF_PATH" 2>/dev/null || true
    systemctl restart frps
    log "域名已设为 $DOMAIN，端口已设为 $NEW_PORT"
    log "请手动到 Cloudflare 控制台添加 A 记录并开启橙色云"
    read -rp "按回车返回菜单..."
}
auto_domain(){
    read -rp "请输入完整子域名 (如 auth.example.com): " DOMAIN
    [[ -z $DOMAIN ]] && { warn "域名为空，返回菜单"; return; }
    # 读取或交互获取 Token
    if [[ -z "${CF_API_TOKEN:-}" ]]; then
        read -rp "请输入 Cloudflare API Token（需 Zone:DNS:Edit 权限）: " TOKEN
        export CF_API_TOKEN=$TOKEN
    fi
    CURRENT_PORT=$(awk -F'=' '/vhostHTTPSPort/ {gsub(/ /,"",$2); print $2}' "$CONF_PATH" 2>/dev/null || echo "8443")
    read -rp "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    # === 端口校验逻辑（新增/修复）
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        warn "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。"
        read -rp "按回车返回菜单..."
        return
    fi
    # ===
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
        log "请手动到 Cloudflare 控制台添加 A 记录并开启橙色云"
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
    log "模板已保存：$CLIENT_TMPL"
    read -rp "按回车返回菜单..."
}
show_status(){
    systemctl is-active frps && log "frps 正在运行" || warn "frps 未运行"
    echo "Token: $(awk -F'"' '/auth.token/ {print $2}' "$CONF_PATH" 2>/dev/null || echo '未找到')"
    echo "访问地址: $(awk -F'"' '/customDomains/ {print $2}' "$CONF_PATH" 2>/dev/null || echo "https://$(curl -s ifconfig.me):8443")"
    read -rp "按回车返回菜单..."
}
uninstall(){
    warn "即将卸载 frps 并删除配置与日志"
    read -rp "确认继续？(y/N): " sure
    [[ $sure =~ ^[Yy]$ ]] || return
    systemctl stop frps.service 2>/dev/null
    systemctl disable frps.service 2>/dev/null
    rm -f /etc/systemd/system/frps.service
    rm -f "$BIN_PATH" "$CONF_PATH" "$LOG_FILE"
    systemctl daemon-reload
    log "frps 已卸载"
    read -rp "按回车返回菜单..."
}
########################### 入口 #####################################
menu_main
