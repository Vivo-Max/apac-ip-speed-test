#!/bin/bash
set -euo pipefail

########################### 基础变量 ###################################
BASE_DIR="$PWD"
BIN_PATH="$BASE_DIR/frps"
CONF_PATH="$BASE_DIR/frps.toml"
LOG_FILE="$BASE_DIR/frps.log"
CLIENT_TMPL="$BASE_DIR/frpc.toml"

########################### 工具函数 ###################################
log() { echo "[INFO] $*"; }
warn(){ echo "[WARN] $*" >&2; }
err() {
    echo "[ERROR] $*" >&2
    read -rp "按回车返回主菜单..."
    menu_main
}
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
        x86_64) echo amd64  ;;
        aarch64)echo arm64  ;;
        *) err "不支持的架构: $(uname -m)" ;;
    esac
}

########################### Cloudflare API ##############################
cf_add_dns(){
    local subdomain=$1 zone_id=$2
    local domain=${subdomain#*.}
    local record_name=${subdomain%.$domain}
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "0.0.0.0")

    # 查是否已存在同名记录
    local resp=$(curl -s -G \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
        --data-urlencode "name=$subdomain" \
        --data-urlencode "type=A")
    local record_id=$(echo "$resp" | jq -r '.result[0].id // empty')

    # 存在则先删除
    if [[ -n $record_id ]]; then
        curl -s -X DELETE \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" >/dev/null
        log "已删除旧 A 记录"
    fi

    # 新建记录
    resp=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
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
        log "DNS 记录已自动添加/更新并开启代理"
        return 0
    else
        warn "API 调用失败：$(echo "$resp" | jq -r '.errors[0].message')"
        return 1
    fi
}

########################### 业务函数 ###################################
_get_token_from_conf() {
    awk '/\[auth\]/{flag=1; next} /\[/{flag=0} flag && /token/{gsub(/.*=|"| /,""); print; exit}' "$CONF_PATH" 2>/dev/null
}

menu_main() {
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
            2) set_domain  ;;
            3) gen_tmpl    ;;
            4) show_status ;;
            5) uninstall   ;;
            6) restart_frps ;;
            7) stop_frps   ;;
            0) log "再见！"; exit 0 ;;
            *) warn "无效选择，请重试";;
        esac
    done
}

restart_frps(){
    log "正在重启 frps..."
    set +e
    if systemctl is-active frps.service >/dev/null 2>&1; then
        systemctl restart frps.service
        log "frps 已重启"
    else
        warn "frps 未运行，将尝试启动..."
        systemctl start frps.service
        if systemctl is-active frps.service >/dev/null 2>&1; then
            log "frps 已启动"
        else
            warn "frps 启动失败，请检查日志 $(journalctl -xeu frps.service | tail -n 5)"
        fi
    fi
    set -e
    read -rp "按回车返回主菜单..."
}

stop_frps(){
    log "正在终止 frps..."
    set +e
    if systemctl is-active frps.service >/dev/null 2>&1; then
        systemctl stop frps.service
        log "frps 已终止"
    else
        warn "frps 未运行，无需终止"
    fi
    set -e
    read -rp "按回车返回主菜单..."
}

install_frps(){
    log "开始安装/更新 frps ..."
    check_root
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
        # 服务端配置：无 [[proxies]]
        cat > "$CONF_PATH" <<EOF
bindPort = 7000
vhostHTTPSPort = 8443

[auth]
token = "$TOKEN"

[log]
level = "info"
EOF
        log "已生成配置文件，Token：$TOKEN"
    else
        TOKEN=$(_get_token_from_conf)
        log "使用已有配置，Token：$TOKEN"
    fi

    set +e
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
    pkill frps 2>/dev/null || true
    systemctl enable frps.service
    systemctl restart frps.service
    if systemctl is-active frps.service >/dev/null 2>&1; then
        log "frps 已启动并设为开机自启"
    else
        warn "frps 启动失败！请检查日志：$(journalctl -xeu frps.service | tail -n 5)"
    fi
    set -e
    read -rp "按回车返回主菜单..."
    menu_main
}

set_domain(){
    log "---- 设置域名 ----"
    echo "1) 仅写入配置（手动去 Cloudflare 添加 DNS）"
    echo "2) 自动添加 DNS 并写入配置（需要 Cloudflare API Token）"
    read -rp "请选择 [1-2]: " MODE
    case $MODE in
        1) manual_domain ;;
        2) auto_domain  ;;
        *) warn "无效选择"; return ;;
    esac
}

manual_domain(){
    read -rp "请输入完整子域名 (如 auth.example.com): " DOMAIN
    [[ -z $DOMAIN ]] && { warn "域名为空，返回菜单"; return; }
    CURRENT_PORT=$(awk -F'=' '/vhostHTTPSPort/ {gsub(/ /,"",$2); print $2}' "$CONF_PATH" 2>/dev/null || echo "8443")
    read -rp "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]]; then
        warn "端口号 '$NEW_PORT' 无效"; read -rp "按回车返回主菜单..."; return; fi
    set +e
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        warn "端口 $NEW_PORT 已被占用"; read -rp "按回车返回主菜单..."; return; fi
    set -e
    sed -i "s/^vhostHTTPSPort.*/vhostHTTPSPort = $NEW_PORT/" "$CONF_PATH"
    sed -i 's|customDomains = \["[^"]*"\]|customDomains = ["'"$DOMAIN"'"]|g' "$CONF_PATH"
    systemctl restart frps.service
    log "域名已设为 $DOMAIN，端口已设为 $NEW_PORT"
    log "请手动到 Cloudflare 控制台添加 A 记录并开启橙色云"
    read -rp "按回车返回主菜单..."
}

auto_domain(){
    read -rp "请输入完整子域名 (如 auth.example.com): " DOMAIN
    [[ -z $DOMAIN ]] && { warn "域名为空，返回菜单"; return; }

    # ① 先输入 API Token
    if [[ -z "${CF_API_TOKEN:-}" ]]; then
        read -rp "请输入 Cloudflare API Token： " TOKEN
        export CF_API_TOKEN=$TOKEN
    fi

    # ② 再输入 Zone ID
    read -rp "请输入该域名在 Cloudflare 的 Zone ID： " ZONE_ID
    [[ -z $ZONE_ID ]] && { warn "Zone ID 为空，回退手动添加"; manual_domain; return; }

    # ③ 端口检查
    CURRENT_PORT=$(awk -F'=' '/vhostHTTPSPort/ {gsub(/ /,"",$2); print $2}' "$CONF_PATH" 2>/dev/null || echo "8443")
    read -rp "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]]; then
        warn "端口号 '$NEW_PORT' 无效"; read -rp "按回车返回主菜单..."; return; fi
    set +e
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        warn "端口 $NEW_PORT 已被占用"; read -rp "按回车返回主菜单..."; return; fi
    set -e

    # ④ 写配置（端口 + 域名）
    sed -i "s/^vhostHTTPSPort.*/vhostHTTPSPort = $NEW_PORT/" "$CONF_PATH"
    sed -i 's|customDomains = \["[^"]*"\]|customDomains = ["'"$DOMAIN"'"]|g' "$CONF_PATH"

    # ⑤ 兜底：若配置里无 [[proxies]] 则追加
    if ! grep -q '^\[\[proxies\]\]' "$CONF_PATH"; then
        cat >> "$CONF_PATH" <<EOF

[[proxies]]
name = "auth-https"
type = "https"
localIP = "localhost"
localPort = 8080
customDomains = ["$DOMAIN"]
EOF
    fi

    # ⑥ 调用 API 添加/更新 DNS
    cf_add_dns "$DOMAIN" "$ZONE_ID"
    systemctl restart frps.service
    read -rp "按回车返回主菜单..."
}

gen_tmpl(){
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    DOMAIN=$(awk -F'"' '/customDomains/ {print $2}' "$CONF_PATH" 2>/dev/null || echo "auth.yourdomain.com")
    TOKEN=$(_get_token_from_conf)
    # >>> 客户端配置：自动带 https 协议头 <<<
    cat > "$CLIENT_TMPL" <<EOF
# 客户端模板（TOML 格式，复制到内网机器使用）
serverAddr = "$SERVER_IP"
serverPort = 7000
token = "$TOKEN"

[[proxies]]
name = "auth-https"
type = "https"
localIP = "localhost"
localPort = 8080
customDomains = ["https://$DOMAIN"]
EOF
    log "模板已保存：$CLIENT_TMPL"
    read -rp "按回车返回主菜单..."
}

show_status(){
    systemctl is-active frps.service >/dev/null 2>&1 && log "frps 正在运行" || warn "frps 未运行"
    TOKEN=$(_get_token_from_conf); TOKEN=${TOKEN:-'未找到'}
    DOMAIN=$(awk -F'"' '/customDomains/ {print $2}' "$CONF_PATH" 2>/dev/null || echo '__DOMAIN_PLACEHOLDER__')
    PORT=$(awk -F'=' '/vhostHTTPSPort/ {gsub(/ /,"",$2); print $2}' "$CONF_PATH" 2>/dev/null || echo "8443")
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "未获取到IP")
    ACCESS_URL="https://$SERVER_IP:$PORT (未配置域名)"
    [[ $DOMAIN != '__DOMAIN_PLACEHOLDER__' ]] && ACCESS_URL="https://$DOMAIN:$PORT"
    echo "Token:     $TOKEN"
    echo "访问地址:  $ACCESS_URL"
    read -rp "按回车返回主菜单..."
}

uninstall(){
    warn "即将卸载 frps 并删除配置与日志"
    read -rp "确认继续？(y/N): " sure
    [[ $sure =~ ^[Yy]$ ]] || { read -rp "按回车返回主菜单..."; return; }
    systemctl stop frps.service 2>/dev/null
    systemctl disable frps.service 2>/dev/null
    rm -f /etc/systemd/system/frps.service
    rm -f "$BIN_PATH" "$CONF_PATH" "$LOG_FILE"
    systemctl daemon-reload
    log "frps 已卸载"
    read -rp "按回车返回主菜单..."
    menu_main
}

########################### 入口 #####################################
menu_main
