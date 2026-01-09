#!/bin/bash
set -euo pipefail
############################  颜色 & 基础信息  ###########################
RED=$(printf '\033[31m') GREEN=$(printf '\032m') YELLOW=$(printf '\033[33m')
NC=$(printf '\033[0m')  BOLD=$(printf '\033[1m')
NAME='frps'
WORK_DIR='/usr/local/frp'
BIN_PATH='/usr/local/bin/frps'
CONF_PATH='/etc/frp/frps.toml'
SERVICE_NAME='frps.service'
LOG_FILE='/var/log/frps.log'

############################  工具函数  #################################
msg()  { echo -e "${BOLD}${GREEN}[INFO]${NC} $*"; }
warn(){ echo -e "${BOLD}${YELLOW}[WARN]${NC} $*"; }
die()  { echo -e "${BOLD}${RED}[ERROR]${NC} $*" >&2; exit 1;}

check_root(){ [[ $EUID -eq 0 ]] || die "请使用 root 运行"; }
command_exists(){ command -v "$1" >/dev/null 2>&1; }

install_deps(){
    if command_exists apt; then
        apt update -y && apt install -y wget tar curl openssl
    elif command_exists yum; then
        yum install -y wget tar curl openssl
    elif command_exists dnf; then
        dnf install -y wget tar curl openssl
    else
        die "未识别的包管理器，请手动安装 wget tar curl openssl"
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
        *) die "不支持的架构: $(uname -m)" ;;
    esac
}

############################  主流程  ###################################
check_root
install_deps

VER=${1:-$(get_latest_ver)}
[ -z "$VER" ] && VER="0.66.0"   # 保底版本
ARCH=$(get_arch)
DOWNLOAD_URL="https://github.com/fatedier/frp/releases/download/v${VER}/frp_${VER}_linux_${ARCH}.tar.gz"

# 已安装且版本相同则跳过
if [[ -x $BIN_PATH ]] && $BIN_PATH --version 2>&1 | grep -q "$VER"; then
    msg "frps v$VER 已安装，跳过下载"
else
    msg "下载 frp v$VER ..."
    wget -qO- "$DOWNLOAD_URL" | tar -xz --strip-components=1 -C /tmp
    install -Dm755 /tmp/frps "$BIN_PATH"
    rm -rf /tmp/frp*
fi

# 自动生成 token（若不存在）
mkdir -p "$(dirname $CONF_PATH)"
if [[ ! -f $CONF_PATH ]]; then
    TOKEN=$(openssl rand -hex 16)
    cat > $CONF_PATH <<EOF
bindPort = 7000
token = "$TOKEN"
vhostHTTPSPort = 443
log.level = "info"
log.file = "$LOG_FILE"
EOF
    msg "已生成配置文件，Token：$TOKEN"
else
    TOKEN=$(awk -F'"' '/token/ {print $2}' $CONF_PATH)
    msg "使用已有配置，Token：$TOKEN"
fi

# systemd 单元
[[ -f /etc/systemd/system/$SERVICE_NAME ]] && systemctl disable --now $SERVICE_NAME 2>/dev/null
cat > /etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=frp Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$WORK_DIR
ExecStartPre=/bin/touch $LOG_FILE
ExecStart=$BIN_PATH -c $CONF_PATH
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now $SERVICE_NAME
msg "frps 已启动并设为开机自启"

############################  客户端模板  ###############################
CLIENT_TMPL=$PWD/frpc.toml

if [[ -f $CLIENT_TMPL ]]; then
    echo
    warn "检测到已存在客户端模板：$CLIENT_TMPL"
    read -rp "是否重新生成并覆盖？(y/N): " OVERWRITE
    if [[ ! $OVERWRITE =~ ^[Yy]$ ]]; then
        msg "保留旧模板，跳过生成"
        # 直接退出函数，不执行后续 cat 生成
        return 0
    fi
fi

# 只有「用户选 y」或「文件不存在」才走到这里
msg "生成客户端配置模板..."
cat > $CLIENT_TMPL <<EOF
# 客户端模板（复制到内网机器使用）
serverAddr = "$(curl -s ifconfig.me)"
serverPort = 7000
token = "$TOKEN"

[[proxies]]
name = "auth-https"
type = "https"
localIP = "localhost"
localPort = 8080
customDomains = ["auth.yourdomain.com"]   # 修改为你的子域名
EOF
msg "模板已保存：$CLIENT_TMPL"

############################  完成提示  ################################
echo
msg "========= 安装完成 ========="
echo "Token    : $TOKEN"
echo "配置路径 : $CONF_PATH"
echo "日志路径 : $LOG_FILE"
echo "客户端模板: $CLIENT_TMPL"
warn "请确保防火墙已放行 7000/443 端口！"
warn "请将 auth.yourdomain.com 解析到本机 IP 并在 Cloudflare 开启代理（如需）"
msg "============================"