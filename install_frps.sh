#!/bin/bash
set -euo pipefail

########################### Systemd 变量 #####################################
FRP_SERVICE="frps.service"
TITLE="🚀 FRP Server 命令行管理菜单"
########################### FRP 安装变量 (TOML 格式) ###########################
BASE_DIR="$PWD" 
BIN_PATH="/usr/local/bin/frps" 
CONF_DIR="/etc/frp" 
CONF_PATH="$CONF_DIR/frps.toml" # 确认使用 TOML 格式
LOG_FILE="/var/log/frps.log" 
CLIENT_TMPL="$BASE_DIR/frpc.toml" # 客户端使用 TOML
CLIENT_INI="$BASE_DIR/frpc.ini" # 兼容 INI 模板生成

########################### 工具函数 #####################################
log() { echo -e "\n[INFO] $*"; }
warn(){ echo -e "\n[WARN] $*" >&2; }
err() { echo -e "\n[ERROR] $*" >&2; exit 1;}
check_root(){ [[ $EUID -eq 0 ]] || err "请使用 root 运行本脚本。"; }
command_exists(){ command -v "$1" >/dev/null 2>&1; }

# 确保安装必要依赖，特别是 jq (用于处理 Cloudflare API)
install_deps(){
    log "正在检查并安装依赖工具 (wget, tar, curl, openssl, jq, dos2unix)..."
    if command -v apt >/dev/null 2>&1; then
        apt update -y && apt install -y wget tar curl openssl jq dos2unix
    elif command -v yum >/dev/null 2>&1; then
        yum install -y wget tar curl openssl jq dos2unix newt
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y wget tar curl openssl jq dos2unix newt
    else
        warn "未识别的包管理器，请手动安装 wget tar curl openssl jq dos2unix"
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
########################### Cloudflare API ###############################
find_zone_id(){
    local subdomain=$1
    local parts=(${subdomain//\./ })
    local len=${#parts[@]}
    
    # 从子域名开始向上查找 Zone
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
        log "正在尝试自动查找 Cloudflare Zone ID..."
        zone_id=$(find_zone_id "$subdomain") 
        [[ -z $zone_id ]] && { warn "警告：未能自动找到合适的 Zone ID。请检查 Token 权限或手动提供 Zone ID。"; return 1; }
    fi
    log "找到 Zone ID: $zone_id"
    
    # 检查现有记录
    local get_resp=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=A&name=$subdomain" \
        -H "Authorization: Bearer $CF_API_TOKEN")
    local num_results=$(echo "$get_resp" | jq '.result | length')

    if [[ $num_results -gt 1 ]]; then
        warn "错误：Cloudflare 上存在多个 A 记录，请手动管理。"
        return 1
    elif [[ $num_results -eq 1 ]]; then
        local record_id=$(echo "$get_resp" | jq -r '.result[0].id')
        local current_content=$(echo "$get_resp" | jq -r '.result[0].content')
        local current_proxied=$(echo "$get_resp" | jq -r '.result[0].proxied')
        
        if [[ "$current_content" == "$server_ip" && "$current_proxied" == "true" ]]; then
            log "DNS 记录已存在且匹配 (IP: $server_ip, 代理: 橙色云)，无需更改。"
            return 0
        else
            log "DNS 记录存在但 IP 或代理状态不匹配，正在更新..."
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
                log "DNS 记录已成功更新为 $server_ip 并开启代理（橙色云模式）。"
                return 0
            else
                warn "API 更新失败：$(echo "$resp" | jq -r '.errors[0].message')"
                return 1
            fi
        fi
    else
        log "未找到现有记录，正在创建新记录..."
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
            log "DNS 记录已成功添加并开启代理（橙色云）。"
            return 0
        else
            warn "API 调用失败：$(echo "$resp" | jq -r '.errors[0].message')"
            return 1
        fi
    fi
}
########################### Systemd 管理函数 #############################

# 简单的命令执行
execute_frps_command() {
    local cmd_type=$1
    echo ""
    log "--- 正在执行 [$cmd_type] $FRP_SERVICE ---"
    
    if [ "$cmd_type" == "status" ]; then
        sudo systemctl status "$FRP_SERVICE" --no-pager
    elif [ "$cmd_type" == "log" ]; then
        log "正在查看实时日志，按 Ctrl+C 退出。"
        sudo journalctl -u "$FRP_SERVICE" -f
    else
        sudo systemctl "$cmd_type" "$FRP_SERVICE"
    fi
    echo "----------------------------"
    read -p "按回车键返回菜单..."
}

########################### FRP 核心配置函数 ##############################
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
# frps.toml (服务端配置)
bindPort = 7000
token = "$TOKEN"
vhostHTTPSPort = 8443
log.to = "$LOG_FILE"
log.level = "info"

[[proxies]]
name = "auth-https"
type = "https"
localIP = "127.0.0.1"
localPort = 8080
customDomains = ["auth.yourdomain.com"]
EOF

        log "已生成 TOML 配置文件 ($CONF_PATH)，Token：$TOKEN"
    else
        TOKEN=$(grep -E '^token\s*=\s*"?([^"]+)"?' "$CONF_PATH" | sed -E 's/token\s*=\s*"?([^"]+)"?/\1/' | head -n 1 2>/dev/null || openssl rand -hex 16)
        log "使用已有 TOML 配置 ($CONF_PATH)，Token：$TOKEN"
    fi

    # Systemd 单元
    [[ -f /etc/systemd/system/$FRP_SERVICE ]] && systemctl disable --now $FRP_SERVICE 2>/dev/null
    cat > /etc/systemd/system/$FRP_SERVICE <<EOF
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
    systemctl enable --now $FRP_SERVICE
    log "frps 已启动并设为开机自启"
    
    echo ""
    log "FRP Server v${VER} 安装/更新完成并已启动。"
    read -p "按回车键返回菜单..."
}

manual_domain(){
    log "--- 手动配置域名和端口 ---"
    read -p "请输入完整子域名 (如 auth.example.com): " DOMAIN
    [[ -z $DOMAIN ]] && { warn "域名为空，返回菜单"; return; }
    
    CURRENT_PORT=$(grep '^vhostHTTPSPort' "$CONF_PATH" | awk -F'[ =]' '{print $NF}' | head -n 1 2>/dev/null || echo "8443")
    read -p "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}

    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        warn "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。"
        read -p "按回车键返回菜单..."
        return
    fi
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        warn "端口 $NEW_PORT 已被占用，请更换或先停用占用服务"
        read -p "按回车键返回菜单..."
        return
    fi
    
    sed -i "s/^\(vhostHTTPSPort\).*/vhostHTTPSPort = $NEW_PORT/" "$CONF_PATH"
    sed -i "/^customDomains\s*=/c\customDomains = [\"$DOMAIN\"]" "$CONF_PATH"
    
    systemctl restart $FRP_SERVICE
    
    echo ""
    log "配置已更新：域名 ${DOMAIN}，端口 ${NEW_PORT}。"
    log "重要：请手动到 Cloudflare 控制台添加 A 记录，IP 指向本机公网 IP，并开启橙色云。"
    read -p "按回车键返回菜单..."
}

auto_domain(){
    log "--- 自动配置域名和 DNS (Cloudflare) ---"
    read -p "请输入完整子域名 (如 auth.example.com): " DOMAIN
    [[ -z $DOMAIN ]] && { warn "域名为空，返回菜单"; return; }
    
    if [[ -z "${CF_API_TOKEN:-}" ]]; then
        read -p "请输入 Cloudflare API Token（需 Zone:DNS:Edit 权限）: " CF_API_TOKEN
        [[ $? -ne 0 || -z $CF_API_TOKEN ]] && { warn "操作取消或 Token 为空"; return; }
    fi
    read -p "请输入 Cloudflare Zone ID（可选，直接回车自动获取）: " ZONE_ID
    
    CURRENT_PORT=$(grep '^vhostHTTPSPort' "$CONF_PATH" | awk -F'[ =]' '{print $NF}' | head -n 1 2>/dev/null || echo "8443")
    read -p "请输入 HTTPS 穿透端口 [当前 $CURRENT_PORT]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    
    if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
        warn "端口号 '$NEW_PORT' 无效，必须是 1 到 65535 之间的数字。"
        read -p "按回车键返回菜单..."
        return
    fi
    if ss -ltn | awk '{print $4}' | grep -q ":${NEW_PORT}$"; then
        warn "端口 $NEW_PORT 已被占用，请更换或先停用占用服务"
        read -p "按回车键返回菜单..."
        return
    fi
    
    sed -i "s/^\(vhostHTTPSPort\).*/vhostHTTPSPort = $NEW_PORT/" "$CONF_PATH"
    sed -i "/^customDomains\s*=/c\customDomains = [\"$DOMAIN\"]" "$CONF_PATH"

    local msg_box="配置已生效。\n"
    if cf_add_dns "$DOMAIN"; then
        msg_box="Cloudflare DNS 记录已自动添加并开启代理（橙色云）。"
    else
        msg_box="Cloudflare DNS 自动添加失败！请检查 Token 或 Zone ID，并手动配置。"
    fi
    systemctl restart $FRP_SERVICE
    
    echo ""
    log "$msg_box"
    read -p "按回车键返回菜单..."
}

gen_tmpl(){
    log "--- 生成客户端配置模板 ---"
    SERVER_IP=$(curl -s ifconfig.me)
    DOMAIN=$(grep -E '^customDomains\s*=\s*\["([^"]+)"\]' "$CONF_PATH" | sed -E 's/customDomains\s*=\s*\["([^"]+)"\]/\1/' | head -n 1 2>/dev/null || echo "auth.yourdomain.com")
    TOKEN=$(grep -E '^token\s*=\s*"?([^"]+)"?' "$CONF_PATH" | sed -E 's/token\s*=\s*"?([^"]+)"?/\1/' | head -n 1 2>/dev/null)
    
    mkdir -p "$BASE_DIR"

    # 生成 TOML 格式客户端模板 (localIP = "localhost" 满足要求)
    cat > "$CLIENT_TMPL" <<EOF
# 客户端模板（TOML 格式，复制到内网机器使用）
serverAddr = "$SERVER_IP"
serverPort = 7000
token = "$TOKEN"

[[proxies]]
name = "auth-https"
type = "https"
localIP = "localhost" # 保证内网服务使用 localhost 访问
localPort = 8080
customDomains = ["$DOMAIN"]
EOF

    # INI 模板 (兼容旧版 frpc)
    cat > "$CLIENT_INI" <<EOF
# 客户端模板（INI 格式，复制到内网机器使用）
[common]
server_addr = $SERVER_IP
server_port = 7000
token = $TOKEN

[auth-https]
type = https
local_ip = localhost # 保证内网服务使用 localhost 访问
local_port = 8080
custom_domains = $DOMAIN
EOF
    
    echo ""
    log "客户端模板已保存到当前目录:"
    echo "TOML 模板：$CLIENT_TMPL"
    echo "INI (旧版兼容) 模板：$CLIENT_INI"
    log "请将任一文件复制到您的内网 frpc 客户端目录并运行。"
    read -p "按回车键返回菜单..."
}

show_config_status(){
    log "--- FRP 配置和运行状态 ---"
    
    # 获取运行状态
    if systemctl is-active $FRP_SERVICE >/dev/null 2>&1; then
        log "frps 状态: 运行中 (Active)"
    else
        warn "frps 状态: 未运行 (Inactive)"
    fi
    
    # 提取配置信息
    TOKEN=$(grep -E '^token\s*=\s*"?([^"]+)"?' "$CONF_PATH" | sed -E 's/token\s*=\s*"?([^"]+)"?/\1/' | head -n 1 2>/dev/null || echo '未找到')
    DOMAIN=$(grep -E '^customDomains\s*=\s*\["([^"]+)"\]' "$CONF_PATH" | sed -E 's/customDomains\s*=\s*\["([^"]+)"\]/\1/' | head -n 1 2>/dev/null || echo '未配置')
    PORT=$(grep '^vhostHTTPSPort' "$CONF_PATH" | awk -F'[ =]' '{print $NF}' | head -n 1 2>/dev/null || echo "8443")
    
    local SERVER_IP=$(curl -s ifconfig.me)
    local ACCESS_URL="https://$SERVER_IP:$PORT"
    if [[ $DOMAIN != '未配置' ]]; then
        if [[ $PORT == 443 ]]; then
            ACCESS_URL="https://$DOMAIN"
        else
            ACCESS_URL="https://$DOMAIN:$PORT"
        fi
    fi
    
    echo "----------------------------"
    echo "配置文件: $CONF_PATH"
    echo "服务器 Token: $TOKEN"
    echo "配置域名/端口: $DOMAIN:$PORT"
    echo "预期公网访问地址: $ACCESS_URL"
    echo "日志位置: $LOG_FILE"
    echo "----------------------------"

    read -p "按回车键返回菜单..."
}

uninstall(){
    echo ""
    read -r -p "警告：即将卸载 frps 并删除配置与日志。确认继续？ (y/N): " CONFIRM
    
    if [[ "$CONFIRM" != [yY] ]]; then
        log "操作取消"
        return
    fi
    
    systemctl stop $FRP_SERVICE 2>/dev/null
    systemctl disable $FRP_SERVICE 2>/dev/null
    rm -f /etc/systemd/system/$FRP_SERVICE
    rm -f "$BIN_PATH"
    rm -f "$CONF_DIR/frps.ini.bak" 2>/dev/null 
    rm -f "$CONF_PATH"
    rm -f "$LOG_FILE"
    systemctl daemon-reload
    
    log "FRP Server 已完全卸载。"
    read -p "按回车键返回菜单..."
}

########################### 主菜单函数 #####################################

main_menu() {
    check_root

    while true; do
        clear
        
        # 动态获取 frps 状态
        local FRP_STATUS=$(sudo systemctl is-active $FRP_SERVICE 2>/dev/null || echo "inactive")
        
        echo "======================================"
        echo "$TITLE"
        echo "======================================"
        echo "当前 frps 状态: $FRP_STATUS"
        echo "--------------------------------------"
        echo "--- 核心配置 ---"
        echo "1. 安装/更新 frps (核心程序)"
        echo "2. 设置域名和穿透端口 (手动配置 DNS)"
        echo "3. 自动配置域名和 DNS (Cloudflare API)"
        echo "4. 生成客户端 frpc 模板 (TOML/INI)"
        echo "5. 查看当前配置和运行状态"
        echo "--- 服务管理 ---"
        echo "6. 启动 frps"
        echo "7. 停止 frps"
        echo "8. 重启 frps"
        echo "9. 查看实时日志 (Ctrl+C 退出)"
        echo "--- 其他 ---"
        echo "10. 卸载 frps (清理文件)"
        echo "0. 退出管理菜单"
        echo "--------------------------------------"
        
        read -r -p "请输入选项 [0-10]: " CHOICE

        case $CHOICE in
            1) install_frps ;;
            2) manual_domain ;;
            3) auto_domain ;;
            4) gen_tmpl ;;
            5) show_config_status ;;
            6) execute_frps_command "start" ;;
            7) execute_frps_command "stop" ;;
            8) execute_frps_command "restart" ;;
            9) execute_frps_command "log" ;;
            10) uninstall ;;
            0) echo "退出管理菜单。再见!"; exit 0 ;;
            *) warn "无效选择，请重试"; read -p "按回车键继续...";;
        esac
    done
}


########################### 入口 #####################################
main_menu
