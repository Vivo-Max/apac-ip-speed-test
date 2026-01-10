#!/bin/bash
set -euo pipefail

########################### 基础变量 ###################################
BASE_DIR="$PWD"
BIN_PATH="$BASE_DIR/frps"
CONF_PATH="$BASE_DIR/frps.toml"
LOG_FILE="$BASE_DIR/frps.log"
CLIENT_TMPL="$BASE_DIR/frpc.toml"

DOMAIN_CACHE="$BASE_DIR/.domain.cache"
CF_CACHE="$BASE_DIR/.cf.cache"   # 保存 API_TOKEN|ZONE_ID

########################### 工具函数 ###################################
log(){ echo "[INFO] $*"; }
warn(){ echo "[WARN] $*" >&2; }
err(){
    echo "[ERROR] $*" >&2
    read -rp "按回车返回主菜单..."
    menu_main
}

check_root(){ [[ $EUID -eq 0 ]] || err "请使用 root 运行"; }

install_deps(){
    if command -v apt >/dev/null; then
        apt update -y && apt install -y wget tar curl openssl jq
    elif command -v yum >/dev/null; then
        yum install -y wget tar curl openssl jq
    elif command -v dnf >/dev/null; then
        dnf install -y wget tar curl openssl jq
    else
        err "不支持的包管理器"
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
        *) err "不支持的架构 $(uname -m)" ;;
    esac
}

########################### Cloudflare DNS ##############################
cf_add_dns(){
    local domain="$1" zone_id="$2" api_token="$3"
    local ip record_id resp

    ip=$(curl -s ifconfig.me || echo "0.0.0.0")

    resp=$(curl -s -G \
        -H "Authorization: Bearer $api_token" \
        "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
        --data-urlencode "type=A" \
        --data-urlencode "name=$domain")

    record_id=$(echo "$resp" | jq -r '.result[0].id // empty')

    if [[ -n $record_id ]]; then
        curl -s -X PUT \
            -H "Authorization: Bearer $api_token" \
            -H "Content-Type: application/json" \
            "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
            --data "{\"type\":\"A\",\"name\":\"$domain\",\"content\":\"$ip\",\"ttl\":120,\"proxied\":true}" >/dev/null
        log "Cloudflare A 记录已更新"
    else
        curl -s -X POST \
            -H "Authorization: Bearer $api_token" \
            -H "Content-Type: application/json" \
            "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
            --data "{\"type\":\"A\",\"name\":\"$domain\",\"content\":\"$ip\",\"ttl\":120,\"proxied\":true}" >/dev/null
        log "Cloudflare A 记录已创建"
    fi
}

########################### 业务函数 ###################################
_get_token(){
    awk '/\[auth\]/{f=1;next}/\[/{f=0}f&&/token/{gsub(/.*=|"| /,"");print;exit}' "$CONF_PATH"
}

menu_main(){
    while true; do
        echo
        echo "======== frps 一键管理菜单 ========"
        echo "1) 安装/更新 frps"
        echo "2) 设置域名 / Cloudflare DNS"
        echo "3) 生成 frpc 客户端模板"
        echo "4) 查看运行状态"
        echo "5) 卸载 frps"
        echo "6) 重启 frps"
        echo "7) 停止 frps"
        echo "0) 退出"
        echo "=================================="
        read -rp "请选择 [0-7]: " c
        case $c in
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

    local ver arch url
    ver=$(get_latest_ver); arch=$(get_arch)
    url="https://github.com/fatedier/frp/releases/download/v$ver/frp_${ver}_linux_${arch}.tar.gz"

    wget -qO- "$url" | tar -xz -C /tmp
    install -Dm755 /tmp/frp_*/frps "$BIN_PATH"
    rm -rf /tmp/frp_*

    if [[ ! -f $CONF_PATH ]]; then
        local token
        token=$(openssl rand -hex 16)
        cat >"$CONF_PATH"<<EOF
bindPort = 7000
vhostHTTPSPort = 8443

[auth]
token = "$token"

[log]
level = "info"
EOF
        log "生成配置，Token：$token"
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
    systemctl is-active frps && log "frps 正常运行" || warn "frps 启动失败"
    read -rp "按回车返回主菜单..."
}

set_domain(){
    read -rp "请输入完整域名 (如 frp.example.com): " domain
    [[ -z $domain ]] && return
    echo "$domain" >"$DOMAIN_CACHE"

    echo "1) 仅保存域名"
    echo "2) 自动更新 Cloudflare A 记录"
    read -rp "请选择 [1-2]: " m

    if [[ $m == 2 ]]; then
        if [[ ! -f $CF_CACHE ]]; then
            read -rp "Cloudflare API Token: " api
            read -rp "Cloudflare Zone ID: " zone
            echo "$api|$zone" >"$CF_CACHE"
        fi
        IFS='|' read -r api zone <"$CF_CACHE"
        cf_add_dns "$domain" "$zone" "$api"
    fi

    read -rp "按回车返回主菜单..."
}

gen_tmpl(){
    local ip token domain
    ip=$(curl -s ifconfig.me)
    token=$(_get_token)
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

restart_frps(){
    systemctl restart frps
    sleep 1
    systemctl is-active frps && log "frps 已重启" || warn "重启失败"
    read -rp "按回车返回主菜单..."
}

stop_frps(){
    systemctl stop frps
    log "frps 已停止"
    read -rp "按回车返回主菜单..."
}

show_status(){
    systemctl is-active frps && log "frps 运行中" || warn "frps 未运行"
    echo "Token: $(_get_token)"
    [[ -f $DOMAIN_CACHE ]] && echo "域名: $(cat "$DOMAIN_CACHE")"
    read -rp "按回车返回主菜单..."
}

uninstall(){
    systemctl disable --now frps 2>/dev/null || true
    rm -f /etc/systemd/system/frps.service "$BIN_PATH" "$CONF_PATH" "$LOG_FILE"
    systemctl daemon-reload
    log "frps 已卸载"
    read -rp "按回车返回主菜单..."
}

########################### 入口 #####################################
menu_main
