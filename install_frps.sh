#!/bin/bash
set -euo pipefail

########################### 基础变量 ###################################
BASE_DIR="$PWD"
BIN_PATH="$BASE_DIR/frps"
CONF_PATH="$BASE_DIR/frps.toml"
LOG_FILE="$BASE_DIR/frps.log"
CLIENT_TMPL="$BASE_DIR/frpc.toml"
DOMAIN_CACHE="$BASE_DIR/.domain.cache"

########################### 工具函数 ###################################
log()  { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
err()  {
    echo "[ERROR] $*" >&2
    read -rp "按回车返回主菜单..."
    menu_main
}

check_root(){ [[ $EUID -eq 0 ]] || err "请使用 root 运行"; }

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
        aarch64) echo arm64 ;;
        *) err "不支持的架构: $(uname -m)" ;;
    esac
}

########################### Cloudflare API ##############################
cf_add_dns(){
    local subdomain=$1 zone_id=$2
    local server_ip
    server_ip=$(curl -s ifconfig.me || echo "0.0.0.0")

    local resp record_id
    resp=$(curl -s -G \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
        --data-urlencode "name=$subdomain" \
        --data-urlencode "type=A")

    record_id=$(echo "$resp" | jq -r '.result[0].id // empty')

    [[ -n $record_id ]] && curl -s -X DELETE \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" >/dev/null

    resp=$(curl -s -X POST \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
        --data "{\"type\":\"A\",\"name\":\"$subdomain\",\"content\":\"$server_ip\",\"ttl\":120,\"proxied\":true}")

    echo "$resp" | jq -e '.success' >/dev/null \
        && log "DNS 已添加并开启 Cloudflare 代理" \
        || warn "DNS 添加失败"
}

########################### 业务函数 ###################################
_get_token_from_conf(){
    awk '/\[auth\]/{f=1;next}/\[/{f=0}f&&/token/{gsub(/.*=|"| /,"");print;exit}' "$CONF_PATH"
}

menu_main(){
    while true; do
        echo
        echo "======== frp 一键管理菜单 ========"
        echo "1) 安装/更新 frps"
        echo "2) 设置域名（仅记录，不写入 frps）"
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
            0) exit 0 ;;
            *) warn "无效选择" ;;
        esac
    done
}

install_frps(){
    check_root
    install_deps

    local ver arch url token
    ver=$(get_latest_ver); arch=$(get_arch)
    url="https://github.com/fatedier/frp/releases/download/v${ver}/frp_${ver}_linux_${arch}.tar.gz"

    wget -qO- "$url" | tar -xz -C /tmp
    install -Dm755 /tmp/frp_*/frps "$BIN_PATH"
    rm -rf /tmp/frp_*

    mkdir -p "$(dirname "$CONF_PATH")"

    if [[ ! -f $CONF_PATH ]]; then
        token=$(openssl rand -hex 16)
        cat >"$CONF_PATH"<<EOF
bindPort = 7000
vhostHTTPSPort = 8443

[auth]
token = "$token"

[log]
level = "info"
EOF
        log "生成 frps 配置，Token：$token"
    fi

    cat >/etc/systemd/system/frps.service<<EOF
[Unit]
Description=frp Server
After=network.target

[Service]
ExecStart=$BIN_PATH -c $CONF_PATH
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now frps
    sleep 1
    systemctl is-active frps >/dev/null && log "frps 正常运行" || warn "frps 启动失败"
    read -rp "按回车返回主菜单..."
}

set_domain(){
    read -rp "请输入域名（如 frp.example.com）: " d
    [[ -n $d ]] && echo "$d" >"$DOMAIN_CACHE" && log "域名已保存（仅用于客户端模板）"
    read -rp "按回车返回主菜单..."
}

gen_tmpl(){
    local ip token domain
    ip=$(curl -s ifconfig.me)
    token=$(_get_token_from_conf)
    domain=$(cat "$DOMAIN_CACHE" 2>/dev/null || echo "frp.example.com")

    cat >"$CLIENT_TMPL"<<EOF
serverAddr = "$ip"
serverPort = 7000
token = "$token"

[[proxies]]
name = "https"
type = "https"
localIP = "127.0.0.1"
localPort = 8080
customDomains = ["$domain"]
EOF
    log "客户端模板已生成：$CLIENT_TMPL"
    read -rp "按回车返回主菜单..."
}

restart_frps(){ systemctl restart frps; sleep 1; systemctl is-active frps && log "已重启"; read -rp "回车继续"; }
stop_frps(){ systemctl stop frps; log "已停止"; read -rp "回车继续"; }

show_status(){
    systemctl is-active frps >/dev/null && log "frps 运行中" || warn "frps 未运行"
    echo "Token: $(_get_token_from_conf)"
    read -rp "按回车返回主菜单..."
}

uninstall(){
    systemctl disable --now frps || true
    rm -f /etc/systemd/system/frps.service "$BIN_PATH" "$CONF_PATH" "$LOG_FILE"
    systemctl daemon-reload
    log "已卸载 frps"
    read -rp "按回车返回主菜单..."
}

########################### 入口 #####################################
menu_main
