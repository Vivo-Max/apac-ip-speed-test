#!/bin/bash
set -euo pipefail

########################### 基础变量 ###################################
WORK_DIR='/usr/local/frp'
BIN_PATH='/usr/local/bin/frps'
CONF_PATH='/etc/frp/frps.toml'
LOG_FILE='/var/log/frps.log'
CLIENT_TMPL="$PWD/frpc.toml"

########################### 工具函数 ###################################
log() { echo "[INFO] $*"; }
warn(){ echo "[WARN] $*"; }
err() { echo "[ERROR] $*" >&2; exit 1;}

install_deps(){
    if command -v apt >/dev/null 2>&1; then
        apt update -y && apt install -y wget tar curl openssl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y wget tar curl openssl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y wget tar curl openssl
    else
        err "未识别的包管理器，请手动安装 wget tar curl openssl"
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

########################### 业务函数 ###################################
menu_main(){
    while true; do
        echo
        echo "======== frp 一键管理菜单 ========"
        echo "1) 安装/更新 frps"
        echo "2) 配置域名"
        echo "3) 生成客户端模板"
        echo "4) 查看运行状态"
        echo "5) 卸载 frps"
        echo "0) 退出"
        echo "=================================="
        read -rp "请选择操作 [0-5]: " choice
        case $choice in
            1) install_frps ;;
            2) set_domain   ;;
            3) gen_tmpl     ;;
            4) show_status  ;;
            5) uninstall    ;;
            0) log "再见！"; exit 0 ;;
            *) warn "无效选择，请重试";;
        esac
    done
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
        cat > "$CONF_PATH" <<EOF
bindPort = 7000
auth.token = "$TOKEN"
vhostHTTPSPort = 8443
[log]
level = "info"
EOF
        log "已生成配置文件，Token：$TOKEN"
    else
        TOKEN=$(awk -F'"' '/auth.token/ {print $2}' "$CONF_PATH")
        log "使用已有配置，Token：$TOKEN"
    fi

    # systemd 单元
    [[ -f /etc/systemd/system/frps.service ]] && systemctl disable --now frps.service 2>/dev/null
    cat > /etc/systemd/system/frps.service <<EOF
[Unit]
Description=frp Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/usr/local/frp
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
    read -rp "请输入完整子域名 (如 auth.example.com): " DOMAIN
    [[ -z $DOMAIN ]] && { warn "域名为空，返回菜单"; return; }
    # 重写配置中的 customDomains 字段
    sed -i "s|customDomains = \[[^]]*\]|customDomains = [\"$DOMAIN\"]|" "$CONF_PATH" 2>/dev/null || true
    systemctl restart frps
    log "域名已设为 $DOMAIN，需解析到本机 IP 并在 Cloudflare 开启代理"
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
    echo "Token:     $(awk -F'"' '/auth.token/ {print $2}' "$CONF_PATH" 2>/dev/null || echo '未找到')"
    echo "访问地址:  $(awk -F'"' '/customDomains/ {print $2}' "$CONF_PATH" 2>/dev/null || echo "https://$(curl -s ifconfig.me):8443")"
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
