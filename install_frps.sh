#!/bin/bash
set -euo pipefail

########################### Systemd & TUI 变量 ###################################
AUTH_SERVICE="auth_server.service"
FRP_SERVICE="frps.service"
HEIGHT=20
WIDTH=70
CHOICE_HEIGHT=12
TITLE="🚀 统一服务器管理菜单"
BACKTITLE="使用方向键选择，回车键确认"
########################### FRP 安装变量 (TOML 格式) ###################################
# 自动设置为用户运行 'auth_manage.sh' 时所在的目录
BASE_DIR="$PWD" 
BIN_PATH="/usr/local/bin/frps" 
CONF_DIR="/etc/frp" 
CONF_PATH="$CONF_DIR/frps.toml" # TOML 格式
LOG_FILE="/var/log/frps.log" 
CLIENT_TMPL="$BASE_DIR/frpc.toml" # 客户端使用 TOML
CLIENT_INI="$BASE_DIR/frpc.ini" # 为兼容旧 frpc，保留 INI 模板生成

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
########################### TUI 辅助执行函数 ##############################

execute_command() {
    local cmd_type=$1
    local service_name=$2
    local tmp_output=$(mktemp)
    
    (
        echo "--- 正在执行 [$cmd_type] $service_name ---"
        case $cmd_type in
            "status")
                sudo systemctl status "$service_name" --no-pager 2>&1 | cat
                ;;
            "log")
                sudo journalctl -u "$service_name" -f
                return 
                ;;
            "restart_all")
                log "正在同时重启 Auth 和 FRP 服务..."
                sudo systemctl restart $AUTH_SERVICE 2>&1
                sudo systemctl restart $FRP_SERVICE 2>&1
                sleep 2
                log "重启完成。"
                ;;
            "status_all")
                log "正在查询两个服务的状态..."
                sudo systemctl status $AUTH_SERVICE $FRP_SERVICE --no-pager 2>&1 | cat
                ;;
            *)
                sudo systemctl "$cmd_type" "$service_name" 2>&1
                ;;
        esac
        echo "----------------------------"
    ) > $tmp_output 2>&1

    whiptail --title "操作结果 ($cmd_type)" --scrolltext --textbox $tmp_output $HEIGHT $WIDTH
    rm -f $tmp_output
}

########################### FRP 核心配置函数 ###################################
install_frps(){
    log "开始安装/更新 frps ..."
    check_root
    install_deps
    VER=${1:-$(get_latest_ver)}
    [ -z "$VER" ] && VER="0.66.0"
    ARCH=$(get_arch)
    URL="https://github.com/fatedier/frp/releases/download/v${VER}/frp_${VER}_linux_${ARCH}.tar.gz"

    if [[ -f "$CONF_DIR/frps.ini" ]]; then
        warn "检测到旧的 frps.ini 文件，已重命名为 frps.ini.bak"
        mv "$CONF_DIR/frps.ini" "$CONF_DIR/frps.ini.bak" 2>/dev/null || true
    fi

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
        
        # 使用 TOML 格式编写配置
        cat > "$CONF_PATH" <<EOF
# frps.toml (推荐格式)
bindPort = 7000
token = "$TOKEN"
vhostHTTPSPort = 8443
log.to = "$LOG_FILE"
log.level = "info"

[[proxies]]
name = "auth-https"
type = "https"
localIP = "127.0.0.1" # 服务端配置使用 127.0.0.1 是标准做法
localPort = 8080
customDomains = ["auth.yourdomain.com"]
EOF

        log "已生成 TOML 配置文件 ($CONF_PATH)，Token：$TOKEN"
    else
        TOKEN=$(grep -E '^token\s*=\s*"?([^"]+)"?' "$CONF_PATH" | sed -E 's/token\s*=\s*"?([^"]+)"?/\1/' | head -n 1 2>/dev/null || openssl rand -hex 16)
        log "使用已有 TOML 配置 ($CONF_PATH)，Token：$TOKEN"
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

manual_domain(){
    DOMAIN=$(whiptail --inputbox "请输入完整子域名 (如 auth.example.com):" $HEIGHT $WIDTH "" 3>&1 1>&2 2>&3)
    [[ -z $DOMAIN ]] && { warn "域名为空，返回菜单"; return; }
    
    CURRENT_PORT=$(grep '^vhostHTTPSPort' "$CONF_PATH" | awk -F'[ =]' '{print $NF}' | head -n 1 2>/dev/null || echo "8443")
    NEW_PORT=$(whiptail --inputbox "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]:" $HEIGHT $WIDTH "$CURRENT_PORT" 3>&1 1>&2 2>&3)
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}

    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        whiptail --msgbox "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。" $HEIGHT $WIDTH
        return
    fi
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        whiptail --msgbox "端口 $NEW_PORT 已被占用，请更换或先停用占用服务" $HEIGHT $WIDTH
        return
    fi
    
    sed -i "s/^\(vhostHTTPSPort\).*/vhostHTTPSPort = $NEW_PORT/" "$CONF_PATH"
    sed -i "/^customDomains\s*=/c\customDomains = [\"$DOMAIN\"]" "$CONF_PATH"
    
    systemctl restart frps
    
    whiptail --msgbox "域名已设为 ${DOMAIN}，端口已设为 ${NEW_PORT}。\n请手动到 Cloudflare 控制台添加 A 记录并开启橙色云。" $HEIGHT $WIDTH
}

auto_domain(){
    DOMAIN=$(whiptail --inputbox "请输入完整子域名 (如 auth.example.com):" $HEIGHT $WIDTH "" 3>&1 1>&2 2>&3)
    [[ -z $DOMAIN ]] && { warn "域名为空，返回菜单"; return; }
    
    if [[ -z "${CF_API_TOKEN:-}" ]]; then
        CF_API_TOKEN=$(whiptail --passwordbox "请输入 Cloudflare API Token（需 Zone:DNS:Edit 权限）:" $HEIGHT $WIDTH 3>&1 1>&2 2>&3)
        [[ $? -ne 0 || -z $CF_API_TOKEN ]] && { warn "操作取消或 Token 为空"; return; }
    fi
    ZONE_ID=$(whiptail --inputbox "请输入 Cloudflare Zone ID（可选，按回车自动获取）:" $HEIGHT $WIDTH "" 3>&1 1>&2 2>&3)
    
    CURRENT_PORT=$(grep '^vhostHTTPSPort' "$CONF_PATH" | awk -F'[ =]' '{print $NF}' | head -n 1 2>/dev/null || echo "8443")
    NEW_PORT=$(whiptail --inputbox "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]:" $HEIGHT $WIDTH "$CURRENT_PORT" 3>&1 1>&2 2>&3)
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        whiptail --msgbox "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。" $HEIGHT $WIDTH
        return
    fi
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        whiptail --msgbox "端口 $NEW_PORT 已被占用，请更换或先停用占用服务" $HEIGHT $WIDTH
        return
    fi
    
    sed -i "s/^\(vhostHTTPSPort\).*/vhostHTTPSPort = $NEW_PORT/" "$CONF_PATH"
    sed -i "/^customDomains\s*=/c\customDomains = [\"$DOMAIN\"]" "$CONF_PATH"

    local msg_box="配置已生效。\n"
    if cf_add_dns "$DOMAIN"; then
        msg_box="Cloudflare DNS 记录已自动添加并开启代理（橙色云）。"
    else
        msg_box="Cloudflare DNS 自动添加失败！\n请手动到 Cloudflare 控制台添加 A 记录并开启橙色云。"
    fi
    systemctl restart frps
    
    whiptail --msgbox "$msg_box" $HEIGHT $WIDTH
}

gen_tmpl(){
    SERVER_IP=$(curl -s ifconfig.me)
    DOMAIN=$(grep -E '^customDomains\s*=\s*\["([^"]+)"\]' "$CONF_PATH" | sed -E 's/customDomains\s*=\s*\["([^"]+)"\]/\1/' | head -n 1 2>/dev/null || echo "auth.yourdomain.com")
    TOKEN=$(grep -E '^token\s*=\s*"?([^"]+)"?' "$CONF_PATH" | sed -E 's/token\s*=\s*"?([^"]+)"?/\1/' | head -n 1 2>/dev/null)
    
    mkdir -p "$BASE_DIR"

    # 生成 TOML 格式客户端模板 (重点修正)
    cat > "$CLIENT_TMPL" <<EOF
# 客户端模板（TOML 格式，复制到内网机器使用）
serverAddr = "$SERVER_IP"
serverPort = 7000
token = "$TOKEN"

[[proxies]]
name = "auth-https"
type = "https"
localIP = "localhost" # **已修正为 localhost**
localPort = 8080
customDomains = ["$DOMAIN"]
EOF

    # 额外生成 INI 格式客户端模板（为了兼容旧版本 frpc）
    cat > "$CLIENT_INI" <<EOF
# 客户端模板（INI 格式，复制到内网机器使用）
[common]
server_addr = $SERVER_IP
server_port = 7000
token = $TOKEN

[auth-https]
type = https
local_ip = localhost # **已修正为 localhost**
local_port = 8080
custom_domains = $DOMAIN
EOF
    
    local msg="客户端模板已保存到:\n"
    msg+="TOML 模板：$CLIENT_TMPL\n"
    msg+="INI (旧版兼容) 模板：$CLIENT_INI\n\n"
    msg+="请将任一文件复制到您的内网 frpc 客户端目录并运行。"
    
    whiptail --msgbox "$msg" $HEIGHT $WIDTH
}

show_config_status(){
    local status_output=$(mktemp)
    
    (
        systemctl is-active frps >/dev/null 2>&1 && log "frps 正在运行" || warn "frps 未运行"
        TOKEN=$(grep -E '^token\s*=\s*"?([^"]+)"?' "$CONF_PATH" | sed -E 's/token\s*=\s*"?([^"]+)"?/\1/' | head -n 1 2>/dev/null || echo '未找到')
        echo "Token: $TOKEN"
        
        local domain=$(grep -E '^customDomains\s*=\s*\["([^"]+)"\]' "$CONF_PATH" | sed -E 's/customDomains\s*=\s*\["([^"]+)"\]/\1/' | head -n 1 2>/dev/null || echo '未配置')
        local port=$(grep '^vhostHTTPSPort' "$CONF_PATH" | awk -F'[ =]' '{print $NF}' | head -n 1 2>/dev/null || echo "8443")
        
        local access="https://$(curl -s ifconfig.me):$port"
        if [[ $domain != '未配置' ]]; then
            if [[ $port == 443 ]]; then
                access="https://$domain"
            else
                access="https://$domain:$port"
            fi
        fi
        echo "配置域名/端口: $domain:$port"
        echo "配置文件: $CONF_PATH"
        echo "预期访问地址: $access"
        echo "日志位置: $LOG_FILE"
    ) > "$status_output" 2>&1

    whiptail --title "FRP 配置状态" --scrolltext --textbox "$status_output" $HEIGHT $WIDTH
    rm -f "$status_output"
}

uninstall(){
    if ! whiptail --yesno "警告：即将卸载 frps 并删除配置与日志。确认继续？" $HEIGHT $WIDTH; then
        log "操作取消"
        return
    fi
    
    systemctl stop frps.service 2>/dev/null
    systemctl disable frps.service 2>/dev/null
    rm -f /etc/systemd/system/frps.service
    rm -f "$BIN_PATH"
    rm -f "$CONF_DIR/frps.ini.bak" 2>/dev/null 
    rm -f "$CONF_PATH"
    rm -f "$LOG_FILE"
    systemctl daemon-reload
    log "frps 已卸载"
    
    whiptail --msgbox "FRP Server 已完全卸载。" $HEIGHT $WIDTH
}
########################### TUI 菜单函数 ##############################

# 子菜单 (Systemd 操作)
submenu() {
    SERVICE=$1
    if [ "$SERVICE" == "$AUTH_SERVICE" ]; then
        SUB_TITLE="VPro Auth Server (Go程序) 管理"
    else
        SUB_TITLE="FRP Server (frps) 管理"
    fi

    CHOICE=$(whiptail --title "$SUB_TITLE" --menu "请选择操作:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
        "start" "启动服务" \
        "stop" "停止服务" \
        "restart" "重启服务" \
        "status" "查看详细状态" \
        "log" "查看实时日志 (Ctrl+C 退出)" \
        3>&1 1>&2 2>&3)

    if [ $? -eq 0 ]; then
        execute_command "$CHOICE" "$SERVICE"
    fi
}

# FRP 配置菜单 (安装/域名/卸载等)
frps_config_menu() {
    clear
    
    while true; do
        CHOICE=$(whiptail --title "FRP 配置与安装菜单" --menu "请选择 FRP 相关的配置操作:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
            "1" "安装/更新 frps (核心程序)" \
            "2" "设置域名和穿透端口" \
            "3" "生成客户端 frpc 模板" \
            "4" "查看当前配置状态" \
            "5" "卸载 frps (清理文件)" \
            "r" "返回主菜单" \
            3>&1 1>&2 2>&3)
            
        if [ $? -ne 0 ] || [ "$CHOICE" == "r" ]; then
            return
        fi
        
        case $CHOICE in
            1) 
                install_frps
                ;;
            2) 
                MODE_CHOICE=$(whiptail --title "域名配置模式" --menu "请选择域名配置模式:" $HEIGHT $WIDTH $CHOICE_HEIGHT \
                    "1" "仅写入配置（手动添加 DNS）" \
                    "2" "自动添加 DNS 并写入配置（需 Cloudflare API）" \
                    3>&1 1>&2 2>&3)
                
                if [ $? -eq 0 ]; then
                    if [ "$MODE_CHOICE" == "1" ]; then
                        manual_domain
                    elif [ "$MODE_CHOICE" == "2" ]; then
                        auto_domain
                    fi
                fi
                ;;
            3) 
                gen_tmpl
                ;;
            4) 
                show_config_status
                ;;
            5) 
                uninstall
                ;;
            *)
                whiptail --msgbox "无效选项: $CHOICE" $HEIGHT $WIDTH
                ;;
        esac
    done
}


########################### 入口 & 主循环 #####################################
check_root
check_whiptail

while true; do
    clear
    # 动态获取并设置状态标签
    AUTH_STATUS=$(sudo systemctl is-active $AUTH_SERVICE 2>/dev/null || echo "inactive")
    FRP_STATUS=$(sudo systemctl is-active $FRP_SERVICE 2>/dev/null || echo "inactive")
    
    MENU_TEXT="Auth状态: $AUTH_STATUS | FRP状态: $FRP_STATUS\n\n请选择操作类别:"

    CHOICE=$(whiptail --title "$TITLE" --backtitle "$BACKTITLE" --menu "$MENU_TEXT" $HEIGHT $WIDTH $CHOICE_HEIGHT \
        "1" "管理 VPro Auth Server (Systemd)" \
        "2" "管理 FRP Server (Systemd)" \
        "3" "同时重启所有服务" \
        "4" "查看所有服务状态" \
        "5" "FRP 安装、配置、卸载" \
        "0" "退出管理菜单" \
        3>&1 1>&2 2>&3)

    if [ $? -ne 0 ] || [ "$CHOICE" == "0" ]; then
        echo "退出管理菜单。再见!"
        exit 0
    fi

    case $CHOICE in
        1)
            submenu $AUTH_SERVICE
            ;;
        2)
            submenu $FRP_SERVICE
            ;;
        3)
            execute_command "restart_all"
            ;;
        4)
            execute_command "status_all"
            ;;
        5)
            frps_config_menu
            ;;
        *)
            warn "无效选择，请重试";
            ;;
    esac
done
