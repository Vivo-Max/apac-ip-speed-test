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

########################### 主流程 ###################################
[[ $EUID -eq 0 ]] || err "请使用 root 运行"
install_deps

VER=${1:-$(get_latest_ver)}
[ -z "$VER" ] && VER="0.66.0"
ARCH=$(get_arch)
URL="https://github.com/fatedier/frp/releases/download/v${VER}/frp_${VER}_linux_${ARCH}.tar.gz"

# 1. 下载/安装
if [[ -x $BIN_PATH ]] && $BIN_PATH --version 2>&1 | grep -q "$VER"; then
    log "frps v$VER 已安装，跳过下载"
else
    log "下载 frp v$VER ..."
    wget -qO- "$URL" | tar -xz --strip-components=1 -C /tmp
    install -Dm755 /tmp/frps "$BIN_PATH"
    rm -rf /tmp/frp*
fi

# 2. 生成/更新配置
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

# 3. 交互：绑定域名
read -rp "是否绑定自己的子域名（如 auth.example.com）？(y/N): " BIND
if [[ $BIND =~ ^[Yy]$ ]]; then
    read -rp "请输入完整子域名: " DOMAIN
    [ -z "$DOMAIN" ] && warn "域名为空，将使用 IP:8443 访问"
else
    DOMAIN=""
fi

# 4. systemd 单元
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

# 5. 客户端模板（交互覆盖）
if [[ -f $CLIENT_TMPL ]]; then
    read -rp "检测到已存在 $CLIENT_TMPL，是否覆盖？(y/N): " OV
    [[ $OV =~ ^[Yy]$ ]] || { log "保留旧模板，跳过生成"; exit 0; }
fi

SERVER_IP=$(curl -s ifconfig.me)
cat > "$CLIENT_TMPL" <<EOF
# 客户端模板（复制到内网机器使用）
serverAddr = "$SERVER_IP"
serverPort = 7000
auth.token = "$TOKEN"

[[proxies]]
name = "auth-https"
type = https
localIP = "127.0.0.1"
localPort = 8080
customDomains = ["${DOMAIN:-auth.yourdomain.com}"]   # 修改为你的子域名
EOF
log "模板已保存：$CLIENT_TMPL"

# 6. 完成提示
echo
echo "========= 安装完成 ========="
echo "Token     : $TOKEN"
echo "配置路径  : $CONF_PATH"
echo "日志路径  : $LOG_FILE"
echo "客户端模板: $CLIENT_TMPL"
if [[ -n $DOMAIN ]]; then
    echo "访问地址  : https://$DOMAIN（需解析到本机 IP）"
else
    echo "访问地址  : https://$SERVER_IP:8443"
fi
echo "请确保防火墙已放行 7000/8443 端口！"
echo "============================"
