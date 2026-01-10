#!/bin/bash
set -euo pipefail

########################### TUI & Systemd 变量 ###################################
AUTH_SERVICE="auth_server.service" # 保留，虽然本脚本不管理它，但结构上可以兼容
FRP_SERVICE="frps.service"
HEIGHT=20
WIDTH=70
CHOICE_HEIGHT=12
TITLE="🚀 FRP 服务器管理菜单"
BACKTITLE="使用方向键选择，数字键快捷选择，回车键确认"

########################### FRP 安装变量 (使用系统路径) ###################################
BASE_DIR="$PWD" # 保留当前目录，仅用于客户端模板和非系统文件，不用于服务配置
BIN_PATH="/usr/local/bin/frps" # 可执行文件安装路径
CONF_DIR="/etc/frp" # 配置目录安装路径
CONF_PATH="$CONF_DIR/frps.ini" # 配置文件路径统一改为 .ini
LOG_FILE="/var/log/frps.log" # 系统日志文件
CLIENT_TMPL="$BASE_DIR/frpc.ini" # 客户端模板 (改为 INI 兼容)

########################### 工具函数 ###################################
log() { echo "[INFO] $*"; }
warn(){ echo "[WARN] $*" >&2; }
err() { echo "[ERROR] $*" >&2; exit 1;}
check_root(){ [[ $EUID -eq 0 ]] || err "请使用 root 运行"; }
command_exists(){ command -v "$1" >/dev/null 2>&1; }

# 检查 whiptail 依赖
check_whiptail() {
    if ! command_exists whiptail; then
        echo "whiptail 未安装。正在尝试安装..."
        install_deps
        if ! command_exists whiptail; then
            err "whiptail 安装失败。请手动安装 (sudo apt install whiptail 或 sudo yum install newt)"
        fi
    fi
}

install_deps(){
    if command -v apt >/dev/null 2>&1; then
        apt update -y && apt install -y wget tar curl openssl jq dos2unix whiptail
    elif command -v yum >/dev/null 2>&1; then
        yum install -y wget tar curl openssl jq dos2unix newt
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y wget tar curl openssl jq dos2unix newt
    else
        warn "未识别的包管理器，请手动安装 wget tar curl openssl jq dos2unix whiptail/newt"
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

    # 注意：这里记录名称应该是 subdomain 本身，而不是 record_name="${subdomain%.*}" 
    # 因为 Cloudflare API 的 name 参数接受完整域名。但为了与原脚本逻辑一致，这里沿用原逻辑
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
                \"name\":\"$subdomain\",
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
########################### 业务函数 (替换 read -rp 为 whiptail) ###################################

# 包装执行命令，并在命令完成后等待用户
execute_command() {
    clear
    echo "--- 正在执行 [$1] $2 ---"
    
    # 临时文件用于捕获输出
    local tmp_output=$(mktemp)
    
    case $1 in
        "status")
            sudo systemctl status "$2" --no-pager > $tmp_output 2>&1
            ;;
        "log")
            # 日志需要用户手动 Ctrl+C 退出，不需要 whiptail box
            sudo journalctl -u "$2" -f
            return # 直接返回，不显示等待
            ;;
        "restart_frps")
            restart_frps_core > $tmp_output 2>&1
            ;;
        "stop_frps")
            stop_frps_core > $tmp_output 2>&1
            ;;
        *)
            # 执行 Systemd 命令 (start, stop, restart)
            sudo systemctl "$1" "$2" > $tmp_output 2>&1
            ;;
    esac
    
    echo "----------------------------"
    
    # 显示结果并等待
    whiptail --title "操作结果" --scrolltext --textbox $tmp_output $HEIGHT $WIDTH
    rm -f $tmp_output
}


# --- 重启 frps 核心逻辑 ---
restart_frps_core(){
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
}

# --- 终止 frps 核心逻辑 ---
stop_frps_core(){
    log "正在终止 frps..."
    if systemctl is-active frps >/dev/null 2>&1; then
        systemctl stop frps
        log "frps 已终止"
    else
        warn "frps 未运行，无需终止"
    fi
}

# --- 核心修复：frps安装/更新，使用 .ini 格式 ---
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
log_file = "$LOG_FILE"
log_level = info

[auth-https]
type = https
local_ip = 127.0.0.1
local_port = 8080
custom_domains = __DOMAIN_PLACEHOLDER__
EOF
        sed -i "s/__TOKEN_PLACEHOLDER__/$TOKEN/g" "$CONF_PATH"
        sed -i "s/custom_domains = .*/custom_domains = auth.yourdomain.com/" "$CONF_PATH" 2>/dev/null || true

        log "已生成「模板化」配置文件 ($CONF_PATH)，Token：$TOKEN"
    else
        TOKEN=$(grep -E '^(token|auth\.token)' "$CONF_PATH" | awk -F'= ' '{print $2}' | tr -d '"' | head -n 1 2>/dev/null || openssl rand -hex 16)
        log "使用已有配置 ($CONF_PATH)，Token：$TOKEN"
    fi

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
    
    whiptail --msgbox "FRP Server v${VER} 安装/更新完成并已启动。" $HEIGHT $WIDTH
}

set_domain(){
    # TUI 替换 set_domain
    MODE=$(whiptail --title "设置域名" --menu "请选择域名配置模式:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
        "1" "仅写入配置（手动去 Cloudflare 添加 DNS）" \
        "2" "自动添加 DNS 并写入配置（需要 Cloudflare API Token）" \
        3>&1 1>&2 2>&3)
        
    if [ $? -ne 0 ]; then
        return # 用户取消
    fi

    case $MODE in
        1) manual_domain ;;
        2) auto_domain ;;
        *) whiptail --msgbox "无效选择" $HEIGHT $WIDTH ;;
    esac
}

manual_domain(){
    # TUI 替换 read -rp DOMAIN
    DOMAIN=$(whiptail --inputbox "请输入完整子域名 (如 auth.example.com):" $HEIGHT $WIDTH "" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z $DOMAIN ]] && { warn "操作取消或域名为空"; return; }
    
    CURRENT_PORT=$(grep -E '^(vhost_https_port|vhostHTTPSPort)' "$CONF_PATH" | awk -F'[ =]' '{print $NF}' | head -n 1 2>/dev/null || echo "8443")
    # TUI 替换 read -rp NEW_PORT
    NEW_PORT=$(whiptail --inputbox "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]:" $HEIGHT $WIDTH "$CURRENT_PORT" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && { warn "操作取消"; return; }
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}

    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        whiptail --msgbox "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。" $HEIGHT $WIDTH
        return
    fi
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        whiptail --msgbox "端口 $NEW_PORT 已被占用，请更换或先停用占用服务" $HEIGHT $WIDTH
        return
    fi
    
    sed -i "s/^\(vhost_https_port\|vhostHTTPSPort\).*/vhost_https_port = $NEW_PORT/" "$CONF_PATH"
    sed -i "s/custom_domains = .*/custom_domains = $DOMAIN/" "$CONF_PATH" 2>/dev/null || true
    
    systemctl restart frps
    whiptail --msgbox "域名已设为 ${DOMAIN}，端口已设为 ${NEW_PORT}。\n请手动到 Cloudflare 控制台添加 A 记录并开启橙色云。" $HEIGHT $WIDTH
}

auto_domain(){
    # TUI 替换 read -rp DOMAIN
    DOMAIN=$(whiptail --inputbox "请输入完整子域名 (如 auth.example.com):" $HEIGHT $WIDTH "" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 || -z $DOMAIN ]] && { warn "操作取消或域名为空"; return; }
    
    # TUI 替换 read -rp CF_API_TOKEN
    if [[ -z "${CF_API_TOKEN:-}" ]]; then
        CF_API_TOKEN=$(whiptail --passwordbox "请输入 Cloudflare API Token（需 Zone:DNS:Edit 权限）:" $HEIGHT $WIDTH 3>&1 1>&2 2>&3)
        [[ $? -ne 0 || -z $CF_API_TOKEN ]] && { warn "操作取消或 Token 为空"; return; }
    fi
    # TUI 替换 read -rp ZONE_ID
    ZONE_ID=$(whiptail --inputbox "请输入 Cloudflare Zone ID（可选，按回车自动获取）:" $HEIGHT $WIDTH "" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && { warn "操作取消"; return; }
    
    CURRENT_PORT=$(grep -E '^(vhost_https_port|vhostHTTPSPort)' "$CONF_PATH" | awk -F'[ =]' '{print $NF}' | head -n 1 2>/dev/null || echo "8443")
    # TUI 替换 read -rp NEW_PORT
    NEW_PORT=$(whiptail --inputbox "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]:" $HEIGHT $WIDTH "$CURRENT_PORT" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && { warn "操作取消"; return; }
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        whiptail --msgbox "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。" $HEIGHT $WIDTH
        return
    fi
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        whiptail --msgbox "端口 $NEW_PORT 已被占用，请更换或先停用占用服务" $HEIGHT $WIDTH
        return
    fi
    
    # 先写入配置 (INI 格式)
    sed -i "s/^\(vhost_https_port\|vhostHTTPSPort\).*/vhost_https_port = $NEW_PORT/" "$CONF_PATH"
    sed -i "s/custom_domains = .*/custom_domains = $DOMAIN/" "$CONF_PATH" 2>/dev/null || true

    local msg_box="自动配置成功。\n"
    if cf_add_dns "$DOMAIN"; then
        log "Cloudflare DNS 记录已自动添加并开启代理。"
        msg_box="Cloudflare DNS 记录已自动添加并开启代理（橙色云）。"
    else
        warn "自动添加失败，已回退为「仅写入配置」"
        msg_box="Cloudflare DNS 自动添加失败！\n请手动到 Cloudflare 控制台添加 A 记录并开启橙色云。"
    fi
    systemctl restart frps
    whiptail --msgbox "$msg_box" $HEIGHT $WIDTH
}

gen_tmpl(){
    SERVER_IP=$(curl -s ifconfig.me)
    DOMAIN=$(grep 'custom_domains' "$CONF_PATH" | awk -F'= ' '{print $2}' | tr -d '"' | head -n 1 2>/dev/null || echo "auth.yourdomain.com")
    TOKEN=$(grep -E '^(token|auth\.token)' "$CONF_PATH" | awk -F'= ' '{print $2}' | tr -d '"' | head -n 1 2>/dev/null)
    
    cat > "$CLIENT_TMPL" <<EOF
# 客户端模板（INI 格式，复制到内网机器使用）
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
    whiptail --msgbox "客户端模板已保存到:\n$CLIENT_TMPL (位于当前目录)\n\n请将此文件复制到您的内网 frpc 客户端目录并运行。" $HEIGHT $WIDTH
}

show_status(){
    local status_output=$(mktemp)
    
    # 捕获状态信息到临时文件
    (
        systemctl is-active frps >/dev/null 2>&1 && log "frps 正在运行" || warn "frps 未运行"
        TOKEN=$(grep -E '^(token|auth\.token)' "$CONF_PATH" | awk -F'= ' '{print $2}' | tr -d '"' | head -n 1 2>/dev/null || echo '未找到')
        echo "Token: $TOKEN"
        
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
        echo "配置文件: $CONF_PATH"
    ) > "$status_output" 2>&1

    whiptail --title "FRP 状态和配置" --scrolltext --textbox "$status_output" $HEIGHT $WIDTH
    rm -f "$status_output"
}

# --- 卸载函数，清理系统路径 ---
uninstall(){
    if ! whiptail --yesno "警告：即将卸载 frps 并删除配置与日志。确认继续？" $HEIGHT $WIDTH; then
        log "操作取消"
        return
    fi
    
    systemctl stop frps.service 2>/dev/null
    systemctl disable frps.service 2>/dev/null
    rm -f /etc/systemd/system/frps.service
    rm -f "$BIN_PATH" # /usr/local/bin/frps
    rm -rf "$CONF_DIR" # /etc/frp 及其内容 (包括 frps.ini)
    rm -f "$LOG_FILE" # /var/log/frps.log
    systemctl daemon-reload
    log "frps 已卸载"
    whiptail --msgbox "FRP Server 已完全卸载。" $HEIGHT $WIDTH
}

########################### 入口 & 主循环 (使用 whiptail) #####################################
menu_main() {
    check_root
    check_whiptail

    while true; do
        clear
        # 动态获取并设置状态标签
        FRP_STATUS=$(systemctl is-active $FRP_SERVICE 2>/dev/null || echo "inactive")
        MENU_TEXT="当前 FRP Server 状态: $FRP_STATUS\n\n请选择操作:"

        CHOICE=$(whiptail --title "$TITLE" --backtitle "$BACKTITLE" --menu "$MENU_TEXT" $HEIGHT $WIDTH $CHOICE_HEIGHT \
            "1" "安装/更新 frps (核心程序)" \
            "2" "设置域名和穿透端口" \
            "3" "生成客户端模板" \
            "4" "查看运行状态" \
            "5" "卸载 frps (清理文件)" \
            "6" "重启 frps" \
            "7" "终止 frps" \
            "0" "退出" \
            3>&1 1>&2 2>&3)

        if [ $? -ne 0 ]; then
            CHOICE="0" # 捕获 ESC 或 Cancel
        fi

        case $CHOICE in
            1) install_frps ;;
            2) set_domain ;;
            3) gen_tmpl ;;
            4) show_status ;;
            5) uninstall ;;
            6) execute_command "restart_frps" $FRP_SERVICE ;;
            7) execute_command "stop_frps" $FRP_SERVICE ;;
            0) log "退出管理菜单。再见!"; exit 0 ;;
            *) warn "无效选择，请重试";;
        esac
    done
}

menu_main
