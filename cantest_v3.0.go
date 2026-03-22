package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apparentlymart/go-cidr/cidr"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

const (
	timeout     = 1 * time.Second 
	maxDuration = 2 * time.Second 
)

// 内存保护阈值：超过此数量切换到流式处理
const maxPreCollectTargets = 5000000  // 500万目标点

// 自定义 intFlag 类型,支持空值
type intFlag struct {
	value int
	set   bool
}

func (i *intFlag) String() string {
	return fmt.Sprintf("%d", i.value)
}

func (i *intFlag) Set(s string) error {
	if s == "" {
		i.value = 200 // 默认值
		i.set = true
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("invalid integer value: %s", s)
	}
	i.value = v
	i.set = true
	return nil
}

// 全局互斥锁，防止进度条闪烁
var progressMu sync.Mutex

// 安全跨平台进度输出（解决 Windows 控制台覆盖不完整问题）
func safePrintProgress(msg string) {
    progressMu.Lock()
    defer progressMu.Unlock()

    // 覆盖整行，避免 Windows 控制台残留字符
    fmt.Printf("\r%-80s", " ")
    fmt.Printf("\r%s", msg)
}


var (
	File            = flag.String("file", "ip.txt", "IP地址文件名称,格式支持 ip:port, ip port, domain, domain:port") // IP地址文件名称
	outFile         = flag.String("outfile", "ip.csv", "输出文件名称")              
	maxThreads      = flag.Int("max", 100, "并发请求最大协程数")            
	speedTest       = flag.Int("speedtest", 5, "下载测速协程数量,设为0禁用测速")                           // 下载测速协程数量
	speedLimit      = flag.Int("speedlimit", 0, "最低下载速度MB/s")                                    // 最低下载速度
	speedTestURL    = flag.String("url", "speed.an226.pp.ua/300MB", "测速文件地址")  // 测速文件地址
	enableTLS       = flag.Bool("tls", true, "是否启用TLS")                                        // TLS是否启用
	TCPurl          = flag.String("tcpurl", "www.speedtest.net", "TCP请求地址")                    // TCP请求地址
	cidrFile        = flag.String("cidrfile", "cidr.txt", "CIDR列表文件名称")                       // CIDR列表文件名称
	asn             = flag.String("asn", "", "从指定ASN下载CIDR列表,例如13335")                    // ASN参数,用于下载CIDR
	cidrPorts       = flag.String("cidr-ports", "", "CIDR展开的端口列表,例如443,2053,50000-60000")  // CIDR端口参数
	updateLocations = flag.Bool("update-locations", false, "更新Cloudflare位置数据")              // 更新位置数据参数
	cidrSpeedTest   = flag.Bool("cidr-speedtest", false, "是否在展开CIDR后立即测速")              // 新增参数:控制CIDR展开后是否测速
	rateLimit       = new(intFlag) // 自定义类型,默认为200
	telegramToken   = flag.String("telegram_token", "", "Telegram Bot TOKEN,用于推送报告")       // 新增Telegram Bot TOKEN
	telegramChatID  = flag.String("telegram_chat_id", "", "Telegram 用户ID,用于推送报告")        // 新增Telegram Chat ID
	presetProxy     = flag.String("preset_proxy", "", "预设SOCKS5代理列表,逗号分隔(如socks5://user:pass@ip:port,socks5://ip:port)") // 新增代理列表参数

	// 新增：随机化扫描参数（默认启用）
	randomizeHosts = flag.Bool("randomize-hosts", true, "随机打乱扫描目标顺序，避免被识别为顺序扫描")
	scanDelay      = flag.Int("scan-delay", 0, "基础扫描延迟毫秒(默认0，建议配合randomize使用)")
	delayJitter    = flag.Int("delay-jitter", 0, "随机延迟抖动范围毫秒(默认0)")

	// Telegram客户端缓存
	telegramClientCache *http.Client
	clientCacheMutex    sync.Mutex

	excludePorts = flag.String("exclude-ports", "", "排除的端口列表,例如80,2052,2053")
)

func init() {
	flag.Var(rateLimit, "rate", "CIDR扫描每秒最大请求数,0表示无限制 (default 200)")
	// 初始化随机种子 - 仅在此处设置一次，避免重复播种
	rand.Seed(time.Now().UnixNano())
}

// Telegram API 响应结构体
type telegramAPIResponse struct {
	Ok          bool   `json:"ok"`
	Description string `json:"description"`
}

type result struct {
	ip          string        // IP地址
	port        int           // 端口
	dataCenter  string        // 数据中心
	region      string        // 地区
	cca2        string        // 国际代码(ISO 3166-1 alpha-2)
	cca1        string        // [融合: 添加第二个脚本的 cca1 字段]
	countryName string        // 中文国家名称
	city        string        // 城市
	latency     string        // 延迟
	tcpDuration time.Duration // TCP请求延迟
}

type speedtestresult struct {
	result
	downloadSpeed float64 // 下载速度
}

type location struct {
	Iata        string  `json:"iata"`         // 数据中心代码
	Lat         float64 `json:"lat"`          // 纬度
	Lon         float64 `json:"lon"`          // 经度
	Cca2        string  `json:"cca2"`         // ISO 3166-1 alpha-2 代码
	Cca1        string  `json:"cca1"`         // [融合: 添加第二个脚本的 cca1 字段]
	Region      string  `json:"region"`       // 地区
	City        string  `json:"city"`         // 城市
	CountryName string  `json:"country_name"` // 中文国家名称
}

// 扫描目标结构体
type scanTarget struct {
	ip   string
	port int
}

// 统一输出格式的函数
// 格式: 发现有效IP 212.104.128.26 端口 443 LAX 
func printValidIP(ip string, port int, dataCenter string, tcpDuration time.Duration, locationMap map[string]location, mu *sync.Mutex) {

	loc, ok := locationMap[dataCenter]
	latencyMS := tcpDuration.Milliseconds()

	if ok {
		// 格式: IATA CountryName City
		locationInfo := fmt.Sprintf("%s %s %s", dataCenter, loc.CountryName, loc.City)
		fmt.Printf("发现有效IP %s 端口 %d 位置信息 %s 延迟 %d 毫秒\n", ip, port, locationInfo, latencyMS)
	} else {
		// 如果位置信息未找到，打印"位置信息未知"
		fmt.Printf("发现有效IP %s 端口 %d 位置信息未知 延迟 %d 毫秒\n", ip, port, latencyMS)
	}
}

// 国家代码到国旗的映射
func getCountryFlag(cca2 string) string {
	flagMap := map[string]string{
		"AD": "🇦🇩", "AE": "🇦🇪", "AF": "🇦🇫", "AG": "🇦🇬", "AI": "🇦🇮", "AL": "🇦🇱", "AM": "🇦🇲", "AO": "🇦🇴",
		"AQ": "🇦🇶", "AR": "🇦🇷", "AS": "🇦🇸", "AT": "🇦🇹", "AU": "🇦🇺", "AW": "🇦🇼", "AX": "🇦🇽", "AZ": "🇦🇿",
		"BA": "🇧🇦", "BB": "🇧🇧", "BD": "🇧🇩", "BE": "🇧🇪", "BF": "🇧🇫", "BG": "🇧🇬", "BH": "🇧🇭", "BI": "🇧🇮",
		"BJ": "🇧🇯", "BL": "🇧🇱", "BM": "🇧🇲", "BN": "🇧🇳", "BO": "🇧🇴", "BQ": "🇧🇶", "BR": "🇧🇷", "BS": "🇧🇸",
		"BT": "🇧🇹", "BV": "🇧🇻", "BW": "🇧🇼", "BY": "🇧🇾", "BZ": "🇧🇿", "CA": "🇨🇦", "CC": "🇨🇨", "CD": "🇨🇩",
		"CF": "🇨🇫", "CG": "🇨🇬", "CH": "🇨🇭", "CI": "🇨🇮", "CK": "🇨🇰", "CL": "🇨🇱", "CM": "🇨🇲", "CN": "🇨🇳",
		"CO": "🇨🇴", "CR": "🇨🇷", "CU": "🇨🇺", "CV": "🇨🇻", "CW": "🇨🇼", "CX": "🇨🇽", "CY": "🇨🇾", "CZ": "🇨🇿",
		"DE": "🇩🇪", "DJ": "🇩🇯", "DK": "🇩🇰", "DM": "🇩🇲", "DO": "🇩🇴", "DZ": "🇩🇿", "EC": "🇪🇨", "EE": "🇪🇪",
		"EG": "🇪🇬", "EH": "🇪🇭", "ER": "🇪🇷", "ES": "🇪🇸", "ET": "🇪🇹", "FI": "🇫🇮", "FJ": "🇫🇯", "FK": "🇫🇰",
		"FM": "🇫🇲", "FO": "🇫🇴", "FR": "🇫🇷", "GA": "🇬🇦", "GB": "🇬🇧", "GD": "🇬🇩", "GE": "🇬🇪", "GF": "🇬🇫",
		"GG": "🇬🇬", "GH": "🇬🇭", "GI": "🇬🇮", "GL": "🇬🇱", "GM": "🇬🇲", "GN": "🇬🇳", "GP": "🇬🇵", "GQ": "🇬🇶",
		"GR": "🇬🇷", "GS": "🇬🇸", "GT": "🇬🇹", "GU": "🇬🇺", "GW": "🇬🇼", "GY": "🇬🇾", "HK": "🇭🇰", "HM": "🇭🇲",
		"HN": "🇭🇳", "HR": "🇭🇷", "HT": "🇭🇹", "HU": "🇭🇺", "ID": "🇮🇩", "IE": "🇮🇪", "IL": "🇮🇱", "IM": "🇮🇲",
		"IN": "🇮🇳", "IO": "🇮🇴", "IQ": "🇮🇶", "IR": "🇮🇷", "IS": "🇮🇸", "IT": "🇮🇹", "JE": "🇯🇪", "JM": "🇯🇲",
		"JO": "🇯🇴", "JP": "🇯🇵", "KE": "🇰🇪", "KG": "🇰🇬", "KH": "🇰🇭", "KI": "🇰🇮", "KM": "🇰🇲", "KN": "🇰🇳",
		"KP": "🇰🇵", "KR": "🇰🇷", "KW": "🇰🇼", "KY": "🇰🇾", "KZ": "🇰🇿", "LA": "🇱🇦", "LB": "🇱🇧", "LC": "🇱🇨",
		"LI": "🇱🇮", "LK": "🇱🇰", "LR": "🇱🇷", "LS": "🇱🇸", "LT": "🇱🇹", "LU": "🇱🇺", "LV": "🇱🇻", "LY": "🇱🇾",
		"MA": "🇲🇦", "MC": "🇲🇨", "MD": "🇲🇩", "ME": "🇲🇪", "MF": "🇲🇫", "MG": "🇲🇬", "MH": "🇲🇭", "MK": "🇲🇰",
		"ML": "🇲🇱", "MM": "🇲🇲", "MN": "🇲🇳", "MO": "🇲🇴", "MP": "🇲🇵", "MQ": "🇲🇶", "MR": "🇲🇷", "MS": "🇲🇸",
		"MT": "🇲🇹", "MU": "🇲🇺", "MV": "🇲🇻", "MW": "🇲🇼", "MX": "🇲🇽", "MY": "🇲🇾", "MZ": "🇲🇿", "NA": "🇳🇦",
		"NC": "🇳🇨", "NE": "🇳🇪", "NF": "🇳🇫", "NG": "🇳🇬", "NI": "🇳🇮", "NL": "🇳🇱", "NO": "🇳🇴", "NP": "🇳🇵",
		"NR": "🇳🇷", "NU": "🇳🇺", "NZ": "🇳🇿", "OM": "🇴🇲", "PA": "🇵🇦", "PE": "🇵🇪", "PF": "🇵🇫", "PG": "🇵🇬",
		"PH": "🇵🇭", "PK": "🇵🇰", "PL": "🇵🇱", "PM": "🇵🇲", "PN": "🇵🇳", "PR": "🇵🇷", "PS": "🇵🇸", "PT": "🇵🇹",
		"PW": "🇵🇼", "PY": "🇵🇾", "QA": "🇶🇦", "RE": "🇷🇪", "RO": "🇷🇴", "RS": "🇷🇸", "RU": "🇷🇺", "RW": "🇷🇼",
		"SA": "🇸🇦", "SB": "🇸🇧", "SC": "🇸🇨", "SD": "🇸🇩", "SE": "🇸🇪", "SG": "🇸🇬", "SH": "🇸🇭", "SI": "🇸🇮",
		"SJ": "🇸🇯", "SK": "🇸🇰", "SL": "🇸🇱", "SM": "🇸🇲", "SN": "🇸🇳", "SO": "🇸🇴", "SR": "🇸🇷", "SS": "🇸🇸",
		"ST": "🇸🇹", "SV": "🇸🇻", "SX": "🇸🇽", "SY": "🇸🇾", "SZ": "🇸🇿", "TC": "🇹🇨", "TD": "🇹🇩", "TF": "🇹🇫",
		"TG": "🇹🇬", "TH": "🇹🇭", "TJ": "🇹🇯", "TK": "🇹🇰", "TL": "🇹🇱", "TM": "🇹🇲", "TN": "🇹🇳", "TO": "🇹🇴",
		"TR": "🇹🇷", "TT": "🇹🇹", "TV": "🇹🇻", "UG": "🇺🇬", "UM": "🇺🇲", "US": "🇺🇸", "UY": "🇺🇾", "UZ": "🇺🇿",
		"VA": "🇻🇦", "VC": "🇻🇨", "VE": "🇻🇪", "VG": "🇻🇬", "VI": "🇻🇮", "VN": "🇻🇳", "VU": "🇻🇺", "WF": "🇼🇫",
		"WS": "🇼🇸", "XK": "🇽🇰", "YE": "🇾🇪", "YT": "🇾🇹", "ZA": "🇿🇦", "ZM": "🇿🇲", "ZW": "🇿🇼", "UNKNOWN": "🌐",
	}

	if flag, ok := flagMap[cca2]; ok {
		return flag
	}
	return "🏳️" // 默认未知国旗
}

// 尝试提升文件描述符的上限
func increaseMaxOpenFiles() {
	fmt.Println("正在尝试提升文件描述符的上限...")
	cmd := exec.Command("bash", "-c", "ulimit -n 10000")
	_, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("提升文件描述符上限时出现错误: %v\n", err)
	} else {
		fmt.Printf("文件描述符上限已提升!\n")
	}
}

// maskBotToken 脱敏 Telegram Bot Token
func maskBotToken(logText string) string {
	re := regexp.MustCompile(`(bot)\d+:[a-zA-Z0-9_-]+`)
	return re.ReplaceAllString(logText, "${1}********************")
}

// escapeMarkdownV2 对字符串进行转义以符合MarkdownV2规范
func escapeMarkdownV2(text string) string {
	var escaped bytes.Buffer
	for _, r := range text {
		switch r {
		case '_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!':
			escaped.WriteRune('\\')
			escaped.WriteRune(r)
		default:
			escaped.WriteRune(r)
		}
	}
	return escaped.String()
}

// maskProxyURL 脱敏代理URL中的认证信息，只保留协议和地址
func maskProxyURL(proxyURL string) string {
	if proxyURL == "" {
		return "直连"
	}
	
	// 检查是否包含认证信息
	if !strings.Contains(proxyURL, "@") {
		return proxyURL // 没有认证信息，直接返回
	}
	
	// 提取协议部分
	parts := strings.SplitN(proxyURL, "://", 2)
	if len(parts) != 2 {
		return proxyURL
	}
	
	protocol := parts[0]
	rest := parts[1]
	
	// 提取地址部分（@之后）
	addrParts := strings.SplitN(rest, "@", 2)
	if len(addrParts) != 2 {
		return proxyURL
	}
	
	// 只返回协议和地址，隐藏认证信息
	return protocol + "://***@" + addrParts[1]
}

// maskError 脱敏错误信息中的敏感内容
func maskError(errStr string) string {
	if errStr == "" {
		return ""
	}
	
	// 脱敏 Bot Token
	errStr = maskBotToken(errStr)
	
	// 脱敏代理认证信息
	errStr = maskProxyURLInError(errStr)
	
	return errStr
}

// maskProxyURLInError 在错误字符串中脱敏代理URL
func maskProxyURLInError(text string) string {
	// 匹配 socks5://user:pass@host:port 或 http://user:pass@host:port
	re := regexp.MustCompile(`([a-zA-Z0-9]+://)[^@]+@([a-zA-Z0-9.:]+)`)
	return re.ReplaceAllString(text, "${1}***@${2}")
}

// createTelegramClientWithProxy 创建带代理的Telegram客户端
func createTelegramClientWithProxy(proxyURL string) (*http.Client, error) {
	var transport *http.Transport
	var err error

	if proxyURL == "" {
		transport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
			// 关键修复：禁用连接复用，解决代理不稳定导致的连接强制关闭问题
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
		}
	} else {
		parsedURL, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("解析代理URL失败: %v", err)
		}

		dialer := &net.Dialer{
			Timeout: 3 * time.Second,
		}

		switch parsedURL.Scheme {
		case "socks5", "socks5h":
			var auth *proxy.Auth
			if parsedURL.User != nil {
				password, _ := parsedURL.User.Password()
				auth = &proxy.Auth{User: parsedURL.User.Username(), Password: password}
			}
			socks5Dialer, err := proxy.SOCKS5("tcp", parsedURL.Host, auth, dialer)
			if err != nil {
				return nil, fmt.Errorf("创建SOCKS5代理失败: %v", err)
			}
			transport = &http.Transport{
				DialContext:       socks5Dialer.(proxy.ContextDialer).DialContext,
				DisableKeepAlives: true,  // 禁用连接复用
				ForceAttemptHTTP2: false,
			}
		default:
			return nil, fmt.Errorf("不支持的代理协议: %s", parsedURL.Scheme)
		}
	}

	// 优化：延长超时时间到60秒，适应文件上传需求
	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	// 测试代理连接 - 使用脱敏后的URL和代理地址
	url := fmt.Sprintf("https://api.telegram.org/bot%s/getMe", *telegramToken)
	maskedURL := maskBotToken(url)
	maskedProxy := maskProxyURL(proxyURL)
	
	fmt.Printf("尝试连接 %s (代理: %s)\n", maskedURL, maskedProxy)
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		// 错误信息脱敏
		maskedErr := maskError(err.Error())
		return nil, fmt.Errorf("代理验证失败: %s (耗时: %v)", maskedErr, time.Since(start))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("代理验证失败,HTTP状态码: %d, 响应: %s (耗时: %v)", resp.StatusCode, string(body), time.Since(start))
	}
	fmt.Printf("连接成功 (代理: %s, 耗时: %v)\n", maskedProxy, time.Since(start))
	return client, nil
}

// getTelegramClient 获取可用的Telegram客户端（带缓存）
func getTelegramClient() *http.Client {
	// 修复：未配置 Telegram Token 或 Chat ID 时，直接返回 nil，不执行任何连接逻辑
	if *telegramToken == "" || *telegramChatID == "" {
		return nil
	}

	clientCacheMutex.Lock()
	defer clientCacheMutex.Unlock()

	if telegramClientCache != nil {
		fmt.Println("使用缓存的Telegram客户端")
		return telegramClientCache
	}

	// 解析代理列表
	proxyList := strings.Split(*presetProxy, ",")
	for _, proxyURL := range proxyList {
		proxyURL = strings.TrimSpace(proxyURL)
		if proxyURL == "" {
			continue
		}
		// 只显示脱敏后的代理地址
		fmt.Printf("尝试通过代理 %s 连接Telegram API...\n", maskProxyURL(proxyURL))
		client, err := createTelegramClientWithProxy(proxyURL)
		if err == nil {
			fmt.Printf("通过代理 %s 建立Telegram会话\n", maskProxyURL(proxyURL))
			telegramClientCache = client
			return client
		}
		// 错误信息脱敏
		maskedErr := maskError(err.Error())
		fmt.Printf("代理 %s 连接Telegram失败: %s\n", maskProxyURL(proxyURL), maskedErr)
	}

	// 所有代理失败,尝试直连
	fmt.Println("所有预设代理失败,尝试直连...")
	client, err := createTelegramClientWithProxy("")
	if err == nil {
		fmt.Println("直连Telegram API成功")
		telegramClientCache = client
		return client
	}
	// 错误信息脱敏
	maskedErr := maskError(err.Error())
	fmt.Printf("直连Telegram API失败: %s\n", maskedErr)
	return nil
}

// invalidateTelegramCache 清除Telegram客户端缓存（辅助函数）
func invalidateTelegramCache() {
	clientCacheMutex.Lock()
	defer clientCacheMutex.Unlock()
	if telegramClientCache != nil {
		telegramClientCache.CloseIdleConnections()
		telegramClientCache = nil
		fmt.Println("Telegram客户端缓存已清除")
	}
}

// sendTelegramMessage 发送Telegram消息(带重试并修正 MarkdownV2 转义)
// 关键修复：每次重试重新获取客户端，支持代理切换
func sendTelegramMessage(message string) bool {
	if *telegramToken == "" || *telegramChatID == "" {
		fmt.Println("未配置Telegram Bot Token或Chat ID,跳过消息推送")
		return false
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", *telegramToken)

	// --- 修正 MarkdownV2 转义逻辑 ---
	// 1. 先进行全量转义
	escapedMessage := escapeMarkdownV2(message)
	// 2. 还原开发者有意使用的 Markdown 语法标记
	escapedMessage = strings.ReplaceAll(escapedMessage, "\\*", "*") // 还原粗体
	escapedMessage = strings.ReplaceAll(escapedMessage, "\\`", "`") // 还原代码块
	escapedMessage = strings.ReplaceAll(escapedMessage, "\\_", "_") // 还原下划线

	payload := map[string]string{
		"chat_id":    *telegramChatID,
		"text":       escapedMessage,
		"parse_mode": "MarkdownV2",
	}

	jsonPayload, _ := json.Marshal(payload)
	const maxRetries = 3
	
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// 关键修复：每次重试都重新获取客户端，确保可以使用新代理
		client := getTelegramClient()
		if client == nil {
			fmt.Println("无法建立网络连接,跳过Telegram消息推送")
			return false
		}

		resp, err := client.Post(apiURL, "application/json", bytes.NewBuffer(jsonPayload))
		if err != nil {
			// 错误信息脱敏
			maskedErr := maskError(err.Error())
			fmt.Printf("Telegram消息推送失败 (尝试 %d/%d): %s\n", attempt, maxRetries, maskedErr)
			
			// 清除缓存，下次重试会尝试新代理
			invalidateTelegramCache()
			
			if attempt == maxRetries {
				return false
			}
			time.Sleep(2 * time.Second)
			continue
		}
		
		// 读取响应体
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var apiResp telegramAPIResponse
		if err := json.Unmarshal(body, &apiResp); err != nil || !apiResp.Ok {
			fmt.Printf("Telegram API错误 (尝试 %d/%d): %s\n", attempt, maxRetries, apiResp.Description)
			
			// 如果是 MarkdownV2 解析错误,尝试降级为纯文本发送,确保消息能送达
			if strings.Contains(apiResp.Description, "can't parse entities") && attempt < maxRetries {
				fmt.Println("检测到Markdown解析错误，尝试降级为纯文本发送...")
				payload["parse_mode"] = "" // 禁用 Markdown
				jsonPayload, _ = json.Marshal(payload)
				// 不清除缓存，这是内容格式问题不是连接问题
				time.Sleep(1 * time.Second)
				continue
			}

			invalidateTelegramCache()
			
			if attempt == maxRetries {
				return false
			}
			time.Sleep(2 * time.Second)
			continue
		}
		fmt.Println("Telegram消息推送成功")
		return true
	}
	return false
}

// sendTelegramFile 发送Telegram文件(带非空检查)
// 关键优化：文件上传使用独立客户端，不污染全局缓存，支持更长超时
func sendTelegramFile(filePath string) bool {
	if *telegramToken == "" || *telegramChatID == "" {
		fmt.Println("未配置Telegram Bot Token或Chat ID,跳过文件推送")
		return false
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("文件 %s 不存在,跳过推送\n", filepath.Base(filePath))
		return false
	}
	fileInfo, _ := os.Stat(filePath)
	if fileInfo.Size() == 0 {
		fmt.Printf("文件 %s 为空,删除并跳过推送\n", filepath.Base(filePath))
		os.Remove(filePath)
		return false
	}

	// 关键优化：文件上传使用独立客户端，避免污染消息通道的缓存
	// 同时支持为文件上传选择最优代理（可以扩展为选择带宽更大的代理）
	var client *http.Client
	var err error
	
	// 优先尝试所有代理，找到能用的（不缓存）
	proxyList := strings.Split(*presetProxy, ",")
	for _, proxyURL := range proxyList {
		proxyURL = strings.TrimSpace(proxyURL)
		if proxyURL == "" {
			continue
		}
		
		fmt.Printf("尝试通过代理 %s 发送文件...\n", maskProxyURL(proxyURL))
		client, err = createTelegramClientWithProxy(proxyURL)
		if err == nil {
			fmt.Printf("通过代理 %s 建立文件上传连接\n", maskProxyURL(proxyURL))
			break
		}
		fmt.Printf("代理 %s 文件上传连接失败: %s\n", maskProxyURL(proxyURL), maskError(err.Error()))
	}
	
	// 所有代理失败则尝试直连
	if client == nil {
		fmt.Println("所有代理失败，尝试直连发送文件...")
		client, err = createTelegramClientWithProxy("")
		if err != nil {
			fmt.Printf("直连文件上传失败: %s\n", maskError(err.Error()))
			return false
		}
		fmt.Println("直连文件上传连接成功")
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", *telegramToken)
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("无法打开文件 %s: %v\n", filePath, err)
		return false
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		fmt.Printf("创建multipart表单失败: %v\n", err)
		return false
	}
	_, err = io.Copy(part, file)
	if err != nil {
		fmt.Printf("复制文件到表单失败: %v\n", err)
		return false
	}
	writer.WriteField("chat_id", *telegramChatID)
	writer.Close()

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		fmt.Printf("创建HTTP请求失败: %v\n", err)
		return false
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		// 错误信息脱敏
		maskedErr := maskError(err.Error())
		fmt.Printf("文件 %s 推送失败: %s\n", filepath.Base(filePath), maskedErr)
		// 文件上传失败不清除消息缓存，因为是独立客户端
		return false
	}
	defer resp.Body.Close()

	var apiResp telegramAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil || !apiResp.Ok {
		fmt.Printf("Telegram API错误: %s\n", apiResp.Description)
		return false
	}

	fmt.Printf("文件 %s 推送成功\n", filepath.Base(filePath))
	return true
}

// 检查IP和端口是否开放并为Cloudflare服务,返回数据中心和延迟
// 修改：支持域名输入，让系统自动解析DNS和处理SNI
func isOpenAndCloudflare(host string, port int) (bool, string, time.Duration) {
	// 判断是否为域名
	isDomain := net.ParseIP(host) == nil

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0,
	}
	
	start := time.Now()
	
	// 对于域名，使用host:port让系统自动解析；对于IP，同样使用host:port
	conn, err := dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, "", 0
	}
	defer conn.Close()
	tcpDuration := time.Since(start)

	// 配置TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	// 如果是域名，设置ServerName用于SNI；如果是IP，不设置（使用IP连接）
	if isDomain {
		tlsConfig.ServerName = host
	}

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
			TLSClientConfig:   tlsConfig,
			ForceAttemptHTTP2: true,
		},
		Timeout: timeout,
	}

	var protocol string
	if *enableTLS {
		protocol = "https://"
	} else {
		protocol = "http://"
	}
	
	// 构建请求URL：域名直接使用，IP使用TCPurl
	var reqURL string
	if isDomain {
		reqURL = protocol + host
	} else {
		reqURL = protocol + *TCPurl
	}
	
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return false, "", tcpDuration
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		return false, "", tcpDuration
	}
	defer resp.Body.Close()

	// 检查是否为Cloudflare服务
	dataCenter := ""
	if server := resp.Header.Get("Server"); strings.Contains(strings.ToLower(server), "cloudflare") {
		dataCenter = resp.Header.Get("CF-RAY")
		if dataCenter != "" {
			parts := strings.Split(dataCenter, "-")
			if len(parts) > 1 {
				dataCenter = parts[1]
			}
		}
	} else {
		return false, "", tcpDuration
	}
	return true, dataCenter, tcpDuration
}

// 测速函数,测试指定host和端口的下载速度
// 修改：支持域名输入，让系统自动解析DNS和处理SNI
func getDownloadSpeed(host string, port int) float64 {
	// 判断是否为域名
	isDomain := net.ParseIP(host) == nil

	var protocol string
	if *enableTLS {
		protocol = "https://"
	} else {
		protocol = "http://"
	}
	speedTestURL := protocol + *speedTestURL
	
	// 创建请求
	req, _ := http.NewRequest("GET", speedTestURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	// 创建TCP连接 - 对于域名，系统会自动解析DNS
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0,
	}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return 0
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
		}
	}(conn)

	if isDomain {
		fmt.Printf("正在测试 %s 端口 %d\n", host, port)
	} else {
		fmt.Printf("正在测试IP %s 端口 %d\n", host, port)
	}
	
	startTime := time.Now()
	
	// 配置TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if isDomain {
		tlsConfig.ServerName = host
	}
	
	// 创建HTTP客户端
	client := http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
			TLSClientConfig: tlsConfig,
		},
		// 设置单个IP测速最长时间为5秒
		Timeout: 5 * time.Second,
	}
	
	// 发送请求
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		if isDomain {
			fmt.Printf("%s 端口 %d 测速无效\n", host, port)
		} else {
			fmt.Printf("IP %s 端口 %d 测速无效\n", host, port)
		}
		return 0
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
		}
	}(resp.Body)

	// 复制响应体到/dev/null，并计算下载速度
	written, _ := io.Copy(io.Discard, resp.Body)
	duration := time.Since(startTime)
	speed := float64(written) / duration.Seconds() / 1024 / 1024

	// 输出结果
	if isDomain {
		fmt.Printf("%s 端口 %d 下载速度 %.2f MB/s\n", host, port, speed)
	} else {
		fmt.Printf("IP %s 端口 %d 下载速度 %.2f MB/s\n", host, port, speed)
	}
	return speed
}

// shuffleStrings 随机打乱字符串切片顺序（保留自版本1，用于兼容）
func shuffleStrings(slice []string) {
	rand.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})
}

// shuffleIntegers 随机打乱整数切片顺序（保留自版本1，用于兼容）
func shuffleIntegers(slice []int) {
	rand.Shuffle(len(slice), func(i, j int) {
		slice[i], slice[j] = slice[j], slice[i]
	})
}

// 主函数入口,处理命令行参数和程序主逻辑
func main() {
	// 强制使用 Go 内置网络解析器,解决安卓/Termux DNS lookup 拒绝连接问题
    os.Setenv("GODEBUG", "netdns=go")
    
	flag.Parse()

	// 参数验证
	if rateLimit.set && rateLimit.value < 0 {
		fmt.Println("[错误] -rate 必须为非负整数")
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage("*⚠️ 错误*\n-rate 必须为非负整数")
			sendTelegramMessage("*🎉 程序运行结束*")
		}
		os.Exit(1)
	}

	if *updateLocations {
		downloadLocations()
		fmt.Println("位置数据已更新到 locations.json")
		return // 如果仅更新位置数据,退出
	}
	
	// 加载位置数据
	var locationMap map[string]location
	// 融合版本1的完整位置数据（包含更多中国城市和机场代码）
	body := `[{"iata":"JOI","lat":-26.304408,"lon":-48.846383,"cca2":"BR","region":"南美洲","city":"若因维利","country_name":"巴西"},{"iata":"POA","lat":-29.9944000244,"lon":-51.1713981628,"cca2":"BR","region":"南美洲","city":"阿雷格里港","country_name":"巴西"},{"iata":"FCO","lat":41.8045005798,"lon":12.2508001328,"cca2":"IT","region":"欧洲","city":"罗马","country_name":"意大利"},{"iata":"RDU","lat":35.93543,"lon":-78.88075,"cca2":"US","region":"北美洲","city":"达勒姆","country_name":"美国"},{"iata":"VTE","lat":17.9757,"lon":102.5683,"cca2":"LA","region":"亚太地区","city":"万象","country_name":"老挝"},{"iata":"COK","lat":9.9312,"lon":76.2673,"cca2":"IN","region":"亚太地区","city":"科钦","country_name":"印度"},{"iata":"NOU","lat":-22.0146007538,"lon":166.212997436,"cca2":"NC","region":"大洋洲","city":"努美阿","country_name":"新喀里多尼亚"},{"iata":"PPT","lat":-17.5536994934,"lon":-149.606994629,"cca2":"PF","region":"大洋洲","city":"塔希提岛","country_name":"法属波利尼西亚"},{"iata":"HNL","lat":21.3187007904,"lon":-157.9219970703,"cca2":"US","region":"北美洲","city":"檀香山","country_name":"美国"},{"iata":"OUA","lat":12.3531999588,"lon":-1.5124200583,"cca2":"BF","region":"非洲","city":"瓦加杜古","country_name":"布基纳法索"},{"iata":"ADB","lat":38.32377,"lon":27.14317,"cca2":"TR","region":"欧洲","city":"伊兹密尔","country_name":"土耳其"},{"iata":"RAO","lat":-21.1363887787,"lon":-47.7766685486,"cca2":"BR","region":"南美洲","city":"里贝朗普雷图","country_name":"巴西"},{"iata":"MNL","lat":14.508600235,"lon":121.019996643,"cca2":"PH","region":"亚太地区","city":"马尼拉","country_name":"菲律宾"},{"iata":"CNN","lat":11.915858,"lon":75.55094,"cca2":"IN","region":"亚太地区","city":"坎努尔","country_name":"印度"},{"iata":"ADL","lat":-34.9431729,"lon":138.5335637,"cca2":"AU","region":"大洋洲","city":"阿德莱德","country_name":"澳大利亚"},{"iata":"RUH","lat":24.9575996399,"lon":46.6987991333,"cca2":"SA","region":"中东","city":"利雅得","country_name":"沙特阿拉伯"},{"iata":"MAO","lat":-3.11286,"lon":-60.01949,"cca2":"BR","region":"南美洲","city":"马瑙斯","country_name":"巴西"},{"iata":"NQN","lat":-38.9490013123,"lon":-68.1557006836,"cca2":"AR","region":"南美洲","city":"内乌肯","country_name":"阿根廷"},{"iata":"EWR","lat":40.6925010681,"lon":-74.1687011719,"cca2":"US","region":"北美洲","city":"纽瓦克","country_name":"美国"},{"iata":"MUC","lat":48.3538017273,"lon":11.7861003876,"cca2":"DE","region":"欧洲","city":"慕尼黑","country_name":"德国"},{"iata":"SMF","lat":38.695400238,"lon":-121.591003418,"cca2":"US","region":"北美洲","city":"萨克拉门托","country_name":"美国"},{"iata":"LIS","lat":38.7812995911,"lon":-9.1359195709,"cca2":"PT","region":"欧洲","city":"里斯本","country_name":"葡萄牙"},{"iata":"BOM","lat":19.0886993408,"lon":72.8678970337,"cca2":"IN","region":"亚太地区","city":"孟买","country_name":"印度"},{"iata":"NNG","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"南宁","country_name":"中国"},{"iata":"QWJ","lat":-22.738,"lon":-47.334,"cca2":"BR","region":"南美洲","city":"阿梅里卡纳","country_name":"巴西"},{"iata":"ATL","lat":33.6366996765,"lon":-84.4281005859,"cca2":"US","region":"北美洲","city":"亚特兰大","country_name":"美国"},{"iata":"BRU","lat":50.9014015198,"lon":4.4844398499,"cca2":"BE","region":"欧洲","city":"布鲁塞尔","country_name":"比利时"},{"iata":"MAD","lat":40.4936,"lon":-3.56676,"cca2":"ES","region":"欧洲","city":"马德里","country_name":"西班牙"},{"iata":"DOH","lat":25.2605946,"lon":51.6137665,"cca2":"QA","region":"中东","city":"多哈","country_name":"卡塔尔"},{"iata":"BSB","lat":-15.79824,"lon":-47.90859,"cca2":"BR","region":"南美洲","city":"巴西利亚","country_name":"巴西"},{"iata":"IXC","lat":30.673500061,"lon":76.7884979248,"cca2":"IN","region":"亚太地区","city":"昌迪加尔","country_name":"印度"},{"iata":"NJF","lat":31.989722,"lon":44.404167,"cca2":"IQ","region":"中东","city":"纳杰夫","country_name":"伊拉克"},{"iata":"XNH","lat":30.9358005524,"lon":46.0900993347,"cca2":"IQ","region":"中东","city":"纳西里耶","country_name":"伊拉克"},{"iata":"HYD","lat":17.2313175201,"lon":78.4298553467,"cca2":"IN","region":"亚太地区","city":"海得拉巴","country_name":"印度"},{"iata":"UIO","lat":-0.1291666667,"lon":-78.3575,"cca2":"EC","region":"南美洲","city":"基多","country_name":"厄瓜多尔"},{"iata":"SHA","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"上海","country_name":"中国"},{"iata":"CWB","lat":-25.5284996033,"lon":-49.1758003235,"cca2":"BR","region":"南美洲","city":"库里蒂巴","country_name":"巴西"},{"iata":"CCU","lat":22.6476933,"lon":88.4349249,"cca2":"IN","region":"亚太地区","city":"加尔各答","country_name":"印度"},{"iata":"LPB","lat":-16.4897,"lon":-68.1193,"cca2":"BO","region":"南美洲","city":"拉巴斯","country_name":"玻利维亚"},{"iata":"CGB","lat":-15.59611,"lon":-56.09667,"cca2":"BR","region":"南美洲","city":"库亚巴","country_name":"巴西"},{"iata":"LHE","lat":31.5216007233,"lon":74.4036026001,"cca2":"PK","region":"亚太地区","city":"拉合尔","country_name":"巴基斯坦"},{"iata":"DUR","lat":-29.6144444444,"lon":31.1197222222,"cca2":"ZA","region":"非洲","city":"德班","country_name":"南非"},{"iata":"JAX","lat":30.4941005707,"lon":-81.6878967285,"cca2":"US","region":"北美洲","city":"杰克逊维尔","country_name":"美国"},{"iata":"GOT","lat":57.6627998352,"lon":12.279800415,"cca2":"SE","region":"欧洲","city":"哥德堡","country_name":"瑞典"},{"iata":"GYE","lat":-2.1894,"lon":-79.8891,"cca2":"EC","region":"南美洲","city":"瓜亚基尔","country_name":"厄瓜多尔"},{"iata":"CAI","lat":30.1219005585,"lon":31.4055995941,"cca2":"EG","region":"非洲","city":"开罗","country_name":"埃及"},{"iata":"TNA","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"淄博","country_name":"中国"},{"iata":"KNU","lat":26.4499,"lon":80.3319,"cca2":"IN","region":"亚太地区","city":"坎普尔","country_name":"印度"},{"iata":"EVN","lat":40.1473007202,"lon":44.3959007263,"cca2":"AM","region":"中东","city":"埃里温","country_name":"亚美尼亚"},{"iata":"CPT","lat":-33.9648017883,"lon":18.6016998291,"cca2":"ZA","region":"非洲","city":"开普敦","country_name":"南非"},{"iata":"OTP","lat":44.5722007751,"lon":26.1021995544,"cca2":"RO","region":"欧洲","city":"布加勒斯特","country_name":"罗马尼亚"},{"iata":"COR","lat":-31.31,"lon":-64.208333,"cca2":"AR","region":"南美洲","city":"科尔多瓦","country_name":"阿根廷"},{"iata":"ABJ","lat":5.292598,"lon":-3.999133,"cca2":"CI","region":"非洲","city":"阿比让","country_name":"科特迪瓦"},{"iata":"KHI","lat":24.9064998627,"lon":67.1607971191,"cca2":"PK","region":"亚太地区","city":"卡拉奇","country_name":"巴基斯坦"},{"iata":"GIG","lat":-22.8099994659,"lon":-43.2505569458,"cca2":"BR","region":"南美洲","city":"里约热内卢","country_name":"巴西"},{"iata":"LUN","lat":-15.371446,"lon":28.317837,"cca2":"ZM","region":"非洲","city":"卢萨卡","country_name":"赞比亚"},{"iata":"DEL","lat":28.5664997101,"lon":77.1031036377,"cca2":"IN","region":"亚太地区","city":"新德里","country_name":"印度"},{"iata":"CGD","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"常德","country_name":"中国"},{"iata":"HRE","lat":-17.9318008423,"lon":31.0928001404,"cca2":"ZW","region":"非洲","city":"哈拉雷","country_name":"津巴布韦"},{"iata":"LIM","lat":-12.021900177,"lon":-77.1143035889,"cca2":"PE","region":"南美洲","city":"利马","country_name":"秘鲁"},{"iata":"YUL","lat":45.4706001282,"lon":-73.7407989502,"cca2":"CA","region":"北美洲","city":"蒙特利尔","country_name":"加拿大"},{"iata":"PBM","lat":5.452831,"lon":-55.187783,"cca2":"SR","region":"南美洲","city":"帕拉马里博","country_name":"苏里南"},{"iata":"BAQ","lat":10.8896,"lon":-74.7808,"cca2":"CO","region":"南美洲","city":"巴兰基利亚","country_name":"哥伦比亚"},{"iata":"XFN","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"襄阳","country_name":"中国"},{"iata":"JXG","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"嘉兴","country_name":"中国"},{"iata":"CNF","lat":-19.624444,"lon":-43.971944,"cca2":"BR","region":"南美洲","city":"贝洛奥里藏特","country_name":"巴西"},{"iata":"BSR","lat":30.5491008759,"lon":47.6621017456,"cca2":"IQ","region":"中东","city":"巴士拉","country_name":"伊拉克"},{"iata":"WAW","lat":52.1656990051,"lon":20.9671001434,"cca2":"PL","region":"欧洲","city":"华沙","country_name":"波兰"},{"iata":"ARU","lat":-21.1413002014,"lon":-50.4247016907,"cca2":"BR","region":"南美洲","city":"阿拉萨图巴","country_name":"巴西"},{"iata":"KWE","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"贵阳","country_name":"中国"},{"iata":"KCH","lat":1.709727,"lon":110.353455,"cca2":"MY","region":"亚太地区","city":"古晋","country_name":"马来西亚"},{"iata":"CTU","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"成都","country_name":"中国"},{"iata":"DAR","lat":-6.8781099319,"lon":39.2025985718,"cca2":"TZ","region":"非洲","city":"达累斯萨拉姆","country_name":"坦桑尼亚"},{"iata":"BNA","lat":36.1245002747,"lon":-86.6781997681,"cca2":"US","region":"北美洲","city":"纳什维尔","country_name":"美国"},{"iata":"WRO","lat":51.106742,"lon":16.983773,"cca2":"PL","region":"欧洲","city":"弗罗茨瓦夫","country_name":"波兰"},{"iata":"IAD","lat":38.94449997,"lon":-77.45580292,"cca2":"US","region":"北美洲","city":"阿什本","country_name":"美国"},{"iata":"DEN","lat":39.8616981506,"lon":-104.672996521,"cca2":"US","region":"北美洲","city":"丹佛","country_name":"美国"},{"iata":"CGP","lat":22.2495995,"lon":91.8133011,"cca2":"BD","region":"亚太地区","city":"吉大港","country_name":"孟加拉国"},{"iata":"KHH","lat":22.5771007538,"lon":120.3499984741,"cca2":"TW","region":"亚太地区","city":"高雄市","country_name":"台湾"},{"iata":"KMG","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"昆明","country_name":"中国"},{"iata":"MXP","lat":45.6305999756,"lon":8.7281103134,"cca2":"IT","region":"欧洲","city":"米兰","country_name":"意大利"},{"iata":"SKG","lat":40.5196990967,"lon":22.9708995819,"cca2":"GR","region":"欧洲","city":"塞萨洛尼基","country_name":"希腊"},{"iata":"DFW","lat":32.8968009949,"lon":-97.0380020142,"cca2":"US","region":"北美洲","city":"达拉斯","country_name":"美国"},{"iata":"SGN","lat":10.8187999725,"lon":106.652000427,"cca2":"VN","region":"亚太地区","city":"胡志明市","country_name":"越南"},{"iata":"MSP","lat":44.8819999695,"lon":-93.2218017578,"cca2":"US","region":"北美洲","city":"明尼阿波利斯","country_name":"美国"},{"iata":"AMS","lat":52.3086013794,"lon":4.7638897896,"cca2":"NL","region":"欧洲","city":"阿姆斯特丹","country_name":"荷兰"},{"iata":"IST","lat":40.9768981934,"lon":28.8145999908,"cca2":"TR","region":"欧洲","city":"伊斯坦布尔","country_name":"土耳其"},{"iata":"HAN","lat":21.221200943,"lon":105.806999206,"cca2":"VN","region":"亚太地区","city":"河内","country_name":"越南"},{"iata":"MSQ","lat":53.9006,"lon":27.599,"cca2":"BY","region":"欧洲","city":"明斯克","country_name":"白俄罗斯"},{"iata":"PIT","lat":40.49150085,"lon":-80.23290253,"cca2":"US","region":"北美洲","city":"匹兹堡","country_name":"美国"},{"iata":"NAG","lat":21.1610714,"lon":79.0024702,"cca2":"IN","region":"亚太地区","city":"那格浦尔","country_name":"印度"},{"iata":"BKK","lat":13.6810998917,"lon":100.747001648,"cca2":"TH","region":"亚太地区","city":"曼谷","country_name":"泰国"},{"iata":"BUF","lat":42.94049835,"lon":-78.73220062,"cca2":"US","region":"北美洲","city":"布法罗","country_name":"美国"},{"iata":"FUK","lat":33.5902,"lon":130.4017,"cca2":"JP","region":"亚太地区","city":"福冈","country_name":"日本"},{"iata":"JDO","lat":-7.2242,"lon":-39.313,"cca2":"BR","region":"南美洲","city":"北茹阿泽鲁","country_name":"巴西"},{"iata":"SDQ","lat":18.4297008514,"lon":-69.6688995361,"cca2":"DO","region":"北美洲","city":"圣多明各","country_name":"多米尼加共和国"},{"iata":"TBS","lat":41.6692008972,"lon":44.95470047,"cca2":"GE","region":"欧洲","city":"第比利斯","country_name":"格鲁吉亚"},{"iata":"TEN","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"铜仁","country_name":"中国"},{"iata":"CLT","lat":35.2140007019,"lon":-80.9430999756,"cca2":"US","region":"北美洲","city":"夏洛特","country_name":"美国"},{"iata":"BAH","lat":26.2707996368,"lon":50.6335983276,"cca2":"BH","region":"中东","city":"麦纳麦","country_name":"巴林"},{"iata":"SJW","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"石家庄","country_name":"中国"},{"iata":"OSL","lat":60.193901062,"lon":11.100399971,"cca2":"NO","region":"欧洲","city":"奥斯陆","country_name":"挪威"},{"iata":"SEA","lat":47.4490013123,"lon":-122.308998108,"cca2":"US","region":"北美洲","city":"西雅图","country_name":"美国"},{"iata":"NRT","lat":35.7647018433,"lon":140.386001587,"cca2":"JP","region":"亚太地区","city":"东京","country_name":"日本"},{"iata":"ZRH","lat":47.4646987915,"lon":8.5491695404,"cca2":"CH","region":"欧洲","city":"苏黎世","country_name":"瑞士"},{"iata":"HBA","lat":-42.883209,"lon":147.331665,"cca2":"AU","region":"大洋洲","city":"霍巴特","country_name":"澳大利亚"},{"iata":"TLL","lat":59.4132995605,"lon":24.8327999115,"cca2":"EE","region":"欧洲","city":"塔林","country_name":"爱沙尼亚"},{"iata":"PMW","lat":-10.2915000916,"lon":-48.3569984436,"cca2":"BR","region":"南美洲","city":"帕尔马斯","country_name":"巴西"},{"iata":"SAP","lat":15.4525995255,"lon":-87.9235992432,"cca2":"HN","region":"南美洲","city":"圣佩德罗苏拉","country_name":"洪都拉斯"},{"iata":"CBR","lat":-35.3069000244,"lon":149.1950073242,"cca2":"AU","region":"大洋洲","city":"堪培拉","country_name":"澳大利亚"},{"iata":"DMM","lat":26.471200943,"lon":49.7979011536,"cca2":"SA","region":"中东","city":"达曼","country_name":"沙特阿拉伯"},{"iata":"KWI","lat":29.226600647,"lon":47.9688987732,"cca2":"KW","region":"中东","city":"科威特城","country_name":"科威特"},{"iata":"ZDM","lat":32.2719,"lon":35.0194,"cca2":"PS","region":"中东","city":"拉马拉","country_name":"巴勒斯坦"},{"iata":"EBB","lat":0.3152,"lon":32.5816,"cca2":"UG","region":"非洲","city":"坎帕拉","country_name":"乌干达"},{"iata":"ARN","lat":59.6519012451,"lon":17.9186000824,"cca2":"SE","region":"欧洲","city":"斯德哥尔摩","country_name":"瑞典"},{"iata":"STR","lat":48.783333,"lon":9.183333,"cca2":"DE","region":"欧洲","city":"斯图加特","country_name":"德国"},{"iata":"VIE","lat":48.1102981567,"lon":16.5697002411,"cca2":"AT","region":"欧洲","city":"维也纳","country_name":"奥地利"},{"iata":"CNX","lat":18.7667999268,"lon":98.962600708,"cca2":"TH","region":"亚太地区","city":"清迈","country_name":"泰国"},{"iata":"ALG","lat":36.6910018921,"lon":3.2154099941,"cca2":"DZ","region":"非洲","city":"阿尔及尔","country_name":"阿尔及利亚"},{"iata":"ALA","lat":43.3521003723,"lon":77.0404968262,"cca2":"KZ","region":"欧洲","city":"阿拉木图","country_name":"哈萨克斯坦"},{"iata":"AAE","lat":36.85596,"lon":7.79207,"cca2":"DZ","region":"非洲","city":"安纳巴","country_name":"阿尔及利亚"},{"iata":"YYC","lat":51.113899231,"lon":-114.019996643,"cca2":"CA","region":"北美洲","city":"卡尔加里","country_name":"加拿大"},{"iata":"LED","lat":59.8003005981,"lon":30.2625007629,"cca2":"RU","region":"欧洲","city":"圣彼得堡","country_name":"俄罗斯"},{"iata":"SOD","lat":-23.54389,"lon":-46.63445,"cca2":"BR","region":"南美洲","city":"索罗卡巴","country_name":"巴西"},{"iata":"SJU","lat":18.411391,"lon":-66.102793,"cca2":"PR","region":"北美洲","city":"圣胡安","country_name":"波多黎各"},{"iata":"MLG","lat":-8.100347,"lon":112.186641,"cca2":"ID","region":"亚太地区","city":"玛琅","country_name":"印度尼西亚"},{"iata":"BCN","lat":41.2971000671,"lon":2.0784599781,"cca2":"ES","region":"欧洲","city":"巴塞罗那","country_name":"西班牙"},{"iata":"SCL","lat":-33.3930015564,"lon":-70.7857971191,"cca2":"CL","region":"南美洲","city":"圣地亚哥","country_name":"智利"},{"iata":"SLC","lat":40.7883987427,"lon":-111.977996826,"cca2":"US","region":"北美洲","city":"盐湖城","country_name":"美国"},{"iata":"VNO","lat":54.6341018677,"lon":25.2858009338,"cca2":"LT","region":"欧洲","city":"维尔纽斯","country_name":"立陶宛"},{"iata":"ICN","lat":37.4691009521,"lon":126.450996399,"cca2":"KR","region":"亚太地区","city":"首尔","country_name":"韩国"},{"iata":"GBE","lat":-24.6282,"lon":25.9231,"cca2":"BW","region":"非洲","city":"哈博罗内","country_name":"博茨瓦纳"},{"iata":"YWG","lat":49.9099998474,"lon":-97.2398986816,"cca2":"CA","region":"北美洲","city":"温尼伯","country_name":"加拿大"},{"iata":"CAW","lat":-21.698299408,"lon":-41.301700592,"cca2":"BR","region":"南美洲","city":"坎波斯戈伊塔卡泽斯","country_name":"巴西"},{"iata":"STI","lat":19.4060993195,"lon":-70.6046981812,"cca2":"DO","region":"北美洲","city":"圣地亚哥","country_name":"多米尼加共和国"},{"iata":"DPS","lat":-8.748169899,"lon":115.1669998169,"cca2":"ID","region":"亚太地区","city":"登巴萨","country_name":"印度尼西亚"},{"iata":"ATH","lat":37.9364013672,"lon":23.9444999695,"cca2":"GR","region":"欧洲","city":"雅典","country_name":"希腊"},{"iata":"BLR","lat":13.7835719,"lon":76.6165937,"cca2":"IN","region":"亚太地区","city":"班加罗尔","country_name":"印度"},{"iata":"DUS","lat":51.2895011902,"lon":6.7667798996,"cca2":"DE","region":"欧洲","city":"杜塞尔多夫","country_name":"德国"},{"iata":"REC","lat":-8.1264896393,"lon":-34.9235992432,"cca2":"BR","region":"南美洲","city":"累西腓","country_name":"巴西"},{"iata":"LLW","lat":-13.980935,"lon":33.761462,"cca2":"MW","region":"非洲","city":"利隆圭","country_name":"马拉维"},{"iata":"SOF","lat":42.6966934204,"lon":23.4114360809,"cca2":"BG","region":"欧洲","city":"索非亚","country_name":"保加利亚"},{"iata":"TYN","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"阳泉","country_name":"中国"},{"iata":"CSX","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"长沙","country_name":"中国"},{"iata":"ARI","lat":-18.348611,"lon":-70.338889,"cca2":"CL","region":"南美洲","city":"阿里卡","country_name":"智利"},{"iata":"CAN","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"广州","country_name":"中国"},{"iata":"VCP","lat":-22.90662,"lon":-47.08576,"cca2":"BR","region":"南美洲","city":"坎皮纳斯","country_name":"巴西"},{"iata":"FUO","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"佛山","country_name":"中国"},{"iata":"MLE","lat":4.1748,"lon":73.50888,"cca2":"MV","region":"亚太地区","city":"马累","country_name":"马尔代夫"},{"iata":"POS","lat":10.5953998566,"lon":-61.3372001648,"cca2":"TT","region":"南美洲","city":"西班牙港","country_name":"特立尼达和多巴哥"},{"iata":"HEL","lat":60.317199707,"lon":24.963300705,"cca2":"FI","region":"欧洲","city":"赫尔辛基","country_name":"芬兰"},{"iata":"ISU","lat":35.5668,"lon":45.4161,"cca2":"IQ","region":"中东","city":"苏莱曼尼亚","country_name":"伊拉克"},{"iata":"RUN","lat":-20.8871002197,"lon":55.5102996826,"cca2":"RE","region":"非洲","city":"圣但尼","country_name":"留尼汪"},{"iata":"NVT","lat":-26.8251,"lon":-49.2695,"cca2":"BR","region":"南美洲","city":"廷博","country_name":"巴西"},{"iata":"SSA","lat":-12.9086112976,"lon":-38.3224983215,"cca2":"BR","region":"南美洲","city":"萨尔瓦多","country_name":"巴西"},{"iata":"AMM","lat":31.7226009369,"lon":35.9931983948,"cca2":"JO","region":"中东","city":"安曼","country_name":"约旦"},{"iata":"ASU","lat":-25.2399997711,"lon":-57.5200004578,"cca2":"PY","region":"南美洲","city":"亚松森","country_name":"巴拉圭"},{"iata":"DUB","lat":53.4212989807,"lon":-6.270070076,"cca2":"IE","region":"欧洲","city":"都柏林","country_name":"爱尔兰"},{"iata":"SUV","lat":-18.11319,"lon":178.43859,"cca2":"FJ","region":"大洋洲","city":"苏瓦","country_name":"斐济"},{"iata":"IAH","lat":29.9843997955,"lon":-95.3414001465,"cca2":"US","region":"北美洲","city":"休斯敦","country_name":"美国"},{"iata":"GUA","lat":14.5832996368,"lon":-90.5274963379,"cca2":"GT","region":"北美洲","city":"危地马拉城","country_name":"危地马拉"},{"iata":"LUX","lat":49.6265983582,"lon":6.211520195,"cca2":"LU","region":"欧洲","city":"卢森堡市","country_name":"卢森堡"},{"iata":"WDH","lat":-22.565587,"lon":17.085334,"cca2":"NA","region":"非洲","city":"温得和克","country_name":"纳米比亚"},{"iata":"BNE","lat":-27.3841991425,"lon":153.117004394,"cca2":"AU","region":"大洋洲","city":"布里斯班","country_name":"澳大利亚"},{"iata":"CEB","lat":10.3074998856,"lon":123.978996277,"cca2":"PH","region":"亚太地区","city":"宿务","country_name":"菲律宾"},{"iata":"FOR","lat":-3.7762799263,"lon":-38.5326004028,"cca2":"BR","region":"南美洲","city":"福塔雷萨","country_name":"巴西"},{"iata":"SAN","lat":32.7336006165,"lon":-117.190002441,"cca2":"US","region":"北美洲","city":"圣迭戈","country_name":"美国"},{"iata":"LYS","lat":45.7263,"lon":5.0908,"cca2":"FR","region":"欧洲","city":"里昂","country_name":"法国"},{"iata":"SIN","lat":1.3501900434,"lon":103.994003296,"cca2":"SG","region":"亚太地区","city":"新加坡","country_name":"新加坡"},{"iata":"TPE","lat":25.0776996613,"lon":121.233001709,"cca2":"TW","region":"亚太地区","city":"台北","country_name":"台湾"},{"iata":"DLC","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"大连","country_name":"中国"},{"iata":"IND","lat":39.717300415,"lon":-86.2944030762,"cca2":"US","region":"北美洲","city":"印第安纳波利斯","country_name":"美国"},{"iata":"MPM","lat":-25.9207992554,"lon":32.5726013184,"cca2":"MZ","region":"非洲","city":"马普托","country_name":"莫桑比克"},{"iata":"HAK","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"澄迈","country_name":"中国"},{"iata":"MEM","lat":35.0424003601,"lon":-89.9766998291,"cca2":"US","region":"北美洲","city":"孟菲斯","country_name":"美国"},{"iata":"PNH","lat":11.5466003418,"lon":104.84400177,"cca2":"KH","region":"亚太地区","city":"金边","country_name":"柬埔寨"},{"iata":"URT","lat":9.1325998306,"lon":99.135597229,"cca2":"TH","region":"亚太地区","city":"素叻他尼","country_name":"泰国"},{"iata":"GRU","lat":-23.4355564117,"lon":-46.4730567932,"cca2":"BR","region":"南美洲","city":"圣保罗","country_name":"巴西"},{"iata":"TLH","lat":30.3964996338,"lon":-84.3503036499,"cca2":"US","region":"北美洲","city":"塔拉哈西","country_name":"美国"},{"iata":"DAD","lat":16.02636,"lon":108.20869,"cca2":"VN","region":"亚太地区","city":"岘港","country_name":"越南"},{"iata":"PAT","lat":25.591299057,"lon":85.0879974365,"cca2":"IN","region":"亚太地区","city":"巴特那","country_name":"印度"},{"iata":"ZAG","lat":45.7429008484,"lon":16.0687999725,"cca2":"HR","region":"欧洲","city":"萨格勒布","country_name":"克罗地亚"},{"iata":"CCP","lat":-36.8201,"lon":-73.0444,"cca2":"CL","region":"南美洲","city":"康塞普西翁","country_name":"智利"},{"iata":"LOS","lat":6.5773701668,"lon":3.321160078,"cca2":"NG","region":"非洲","city":"拉各斯","country_name":"尼日利亚"},{"iata":"MRU","lat":-20.4302005768,"lon":57.6836013794,"cca2":"MU","region":"非洲","city":"路易港","country_name":"毛里求斯"},{"iata":"OMA","lat":41.3031997681,"lon":-95.8940963745,"cca2":"US","region":"北美洲","city":"奥马哈","country_name":"美国"},{"iata":"KJA","lat":56.0153,"lon":92.8932,"cca2":"RU","region":"亚太地区","city":"克拉斯诺亚尔斯克","country_name":"俄罗斯"},{"iata":"SJK","lat":-23.1791,"lon":-45.8872,"cca2":"BR","region":"南美洲","city":"圣若泽杜斯坎波斯","country_name":"巴西"},{"iata":"MFM","lat":22.1495990753,"lon":113.592002869,"cca2":"MO","region":"亚太地区","city":"澳门","country_name":"澳门"},{"iata":"AKL","lat":-37.0080986023,"lon":174.792007446,"cca2":"NZ","region":"大洋洲","city":"奥克兰","country_name":"新西兰"},{"iata":"BOG","lat":4.70159,"lon":-74.1469,"cca2":"CO","region":"南美洲","city":"波哥大","country_name":"哥伦比亚"},{"iata":"MEL","lat":-37.6733016968,"lon":144.843002319,"cca2":"AU","region":"大洋洲","city":"墨尔本","country_name":"澳大利亚"},{"iata":"HFA","lat":32.78492,"lon":34.96069,"cca2":"IL","region":"中东","city":"海法","country_name":"以色列"},{"iata":"SJO","lat":9.9938602448,"lon":-84.2088012695,"cca2":"CR","region":"南美洲","city":"圣何塞","country_name":"哥斯达黎加"},{"iata":"JOG","lat":-7.7881798744,"lon":110.4319992065,"cca2":"ID","region":"亚太地区","city":"日惹","country_name":"印度尼西亚"},{"iata":"CHC","lat":-43.4893989563,"lon":172.5319976807,"cca2":"NZ","region":"大洋洲","city":"克赖斯特彻奇","country_name":"新西兰"},{"iata":"FRA","lat":50.0264015198,"lon":8.543129921,"cca2":"DE","region":"欧洲","city":"法兰克福","country_name":"德国"},{"iata":"SAT","lat":29.429461,"lon":-98.487061,"cca2":"US","region":"北美洲","city":"圣安东尼奥","country_name":"美国"},{"iata":"GEO","lat":6.825648,"lon":-58.163756,"cca2":"GY","region":"南美洲","city":"乔治敦","country_name":"圭亚那"},{"iata":"TGU","lat":14.0608,"lon":-87.2172,"cca2":"HN","region":"南美洲","city":"特古西加尔巴","country_name":"洪都拉斯"},{"iata":"SZX","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"深圳","country_name":"中国"},{"iata":"JED","lat":21.679599762,"lon":39.15650177,"cca2":"SA","region":"中东","city":"吉达","country_name":"沙特阿拉伯"},{"iata":"MIA","lat":25.7931995392,"lon":-80.2906036377,"cca2":"US","region":"北美洲","city":"迈阿密","country_name":"美国"},{"iata":"LHR","lat":51.4706001282,"lon":-0.4619410038,"cca2":"GB","region":"欧洲","city":"伦敦","country_name":"英国"},{"iata":"MRS","lat":43.439271922,"lon":5.2214241028,"cca2":"FR","region":"欧洲","city":"马赛","country_name":"法国"},{"iata":"ORF","lat":36.8945999146,"lon":-76.2012023926,"cca2":"US","region":"北美洲","city":"诺福克","country_name":"美国"},{"iata":"BGR","lat":44.8081,"lon":-68.795,"cca2":"US","region":"北美洲","city":"班戈","country_name":"美国"},{"iata":"BEL","lat":-1.4563,"lon":-48.5013,"cca2":"BR","region":"南美洲","city":"贝伦","country_name":"巴西"},{"iata":"LAS","lat":36.08010101,"lon":-115.1520004,"cca2":"US","region":"北美洲","city":"拉斯维加斯","country_name":"美国"},{"iata":"TUN","lat":36.8510017395,"lon":10.2271995544,"cca2":"TN","region":"非洲","city":"突尼斯","country_name":"突尼斯"},{"iata":"ASK","lat":6.842178,"lon":-5.259932,"cca2":"CI","region":"非洲","city":"亚穆苏克罗","country_name":"科特迪瓦"},{"iata":"OKC","lat":35.46655,"lon":-97.65373,"cca2":"US","region":"北美洲","city":"俄克拉荷马城","country_name":"美国"},{"iata":"BWN","lat":4.903052,"lon":114.939819,"cca2":"BN","region":"亚太地区","city":"斯里巴加湾市","country_name":"文莱"},{"iata":"GUM","lat":13.4834003448,"lon":144.796005249,"cca2":"GU","region":"亚太地区","city":"哈加特纳","country_name":"关岛"},{"iata":"DAC","lat":23.843347,"lon":90.397783,"cca2":"BD","region":"亚太地区","city":"达卡","country_name":"孟加拉国"},{"iata":"VIX","lat":-20.64871,"lon":-41.90857,"cca2":"BR","region":"南美洲","city":"维多利亚","country_name":"巴西"},{"iata":"KIN","lat":17.9951,"lon":-76.7846,"cca2":"JM","region":"北美洲","city":"金斯敦","country_name":"牙买加"},{"iata":"ORD","lat":41.97859955,"lon":-87.90480042,"cca2":"US","region":"北美洲","city":"芝加哥","country_name":"美国"},{"iata":"KIV","lat":46.9277000427,"lon":28.9309997559,"cca2":"MD","region":"欧洲","city":"基希讷乌","country_name":"摩尔多瓦"},{"iata":"YYZ","lat":43.6772003174,"lon":-79.6305999756,"cca2":"CA","region":"北美洲","city":"多伦多","country_name":"加拿大"},{"iata":"ULN","lat":47.8431015015,"lon":106.766998291,"cca2":"MN","region":"亚太地区","city":"乌兰巴托","country_name":"蒙古"},{"iata":"BGW","lat":33.2625007629,"lon":44.2346000671,"cca2":"IQ","region":"中东","city":"巴格达","country_name":"伊拉克"},{"iata":"GYD","lat":40.4674987793,"lon":50.0466995239,"cca2":"AZ","region":"中东","city":"巴库","country_name":"阿塞拜疆"},{"iata":"DXB","lat":25.2527999878,"lon":55.3643989563,"cca2":"AE","region":"中东","city":"迪拜","country_name":"阿联酋"},{"iata":"SYD","lat":-33.9460983276,"lon":151.177001953,"cca2":"AU","region":"大洋洲","city":"悉尼","country_name":"澳大利亚"},{"iata":"LAD","lat":-8.8583698273,"lon":13.2312002182,"cca2":"AO","region":"非洲","city":"罗安达","country_name":"安哥拉"},{"iata":"PHL","lat":39.8718986511,"lon":-75.2410964966,"cca2":"US","region":"北美洲","city":"费城","country_name":"美国"},{"iata":"YHZ","lat":44.64601,"lon":-63.66844,"cca2":"CA","region":"北美洲","city":"哈利法克斯","country_name":"加拿大"},{"iata":"KHN","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"南昌","country_name":"中国"},{"iata":"KGL","lat":-1.9686299563,"lon":30.1394996643,"cca2":"RW","region":"非洲","city":"基加利","country_name":"卢旺达"},{"iata":"MCI","lat":39.2975997925,"lon":-94.7138977051,"cca2":"US","region":"北美洲","city":"堪萨斯城","country_name":"美国"},{"iata":"NBO","lat":-1.319239974,"lon":36.9277992249,"cca2":"KE","region":"非洲","city":"内罗毕","country_name":"肯尼亚"},{"iata":"STL","lat":38.7486991882,"lon":-90.3700027466,"cca2":"US","region":"北美洲","city":"圣路易斯","country_name":"美国"},{"iata":"AKX","lat":50.286922,"lon":57.224121,"cca2":"KZ","region":"欧洲","city":"阿克托比","country_name":"哈萨克斯坦"},{"iata":"HYN","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"台州","country_name":"中国"},{"iata":"BTS","lat":48.1486,"lon":17.1077,"cca2":"SK","region":"欧洲","city":"布拉迪斯拉发","country_name":"斯洛伐克"},{"iata":"CPH","lat":55.6179008484,"lon":12.6560001373,"cca2":"DK","region":"欧洲","city":"哥本哈根","country_name":"丹麦"},{"iata":"OKA","lat":26.1958,"lon":127.646,"cca2":"JP","region":"亚太地区","city":"那霸","country_name":"日本"},{"iata":"BHY","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"北海","country_name":"中国"},{"iata":"TNR","lat":-18.91368,"lon":47.53613,"cca2":"MG","region":"非洲","city":"塔那那利佛","country_name":"马达加斯加"},{"iata":"TXL","lat":52.5597000122,"lon":13.2876996994,"cca2":"DE","region":"欧洲","city":"柏林","country_name":"德国"},{"iata":"HAM","lat":53.6304016113,"lon":9.9882297516,"cca2":"DE","region":"欧洲","city":"汉堡","country_name":"德国"},{"iata":"GYN","lat":-16.69727,"lon":-49.26851,"cca2":"BR","region":"南美洲","city":"戈亚尼亚","country_name":"巴西"},{"iata":"FOC","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"福州","country_name":"中国"},{"iata":"ISB","lat":33.6166992188,"lon":73.0991973877,"cca2":"PK","region":"亚太地区","city":"伊斯兰堡","country_name":"巴基斯坦"},{"iata":"DME","lat":55.4087982178,"lon":37.9062995911,"cca2":"RU","region":"欧洲","city":"莫斯科","country_name":"俄罗斯"},{"iata":"TAO","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"青岛","country_name":"中国"},{"iata":"KUL","lat":2.745579958,"lon":101.709999084,"cca2":"MY","region":"亚太地区","city":"吉隆坡","country_name":"马来西亚"},{"iata":"CLE","lat":41.50069,"lon":-81.68412,"cca2":"US","region":"北美洲","city":"克利夫兰","country_name":"美国"},{"iata":"HGH","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"绍兴","country_name":"中国"},{"iata":"FRU","lat":42.875608,"lon":74.604613,"cca2":"KG","region":"亚太地区","city":"比什凯克","country_name":"吉尔吉斯斯坦"},{"iata":"AMD","lat":23.0225,"lon":72.5714,"cca2":"IN","region":"亚太地区","city":"艾哈迈达巴德","country_name":"印度"},{"iata":"BEY","lat":33.8208999634,"lon":35.4883995056,"cca2":"LB","region":"中东","city":"黎巴嫩","country_name":"黎巴嫩"},{"iata":"BUD","lat":47.4369010925,"lon":19.2555999756,"cca2":"HU","region":"欧洲","city":"布达佩斯","country_name":"匈牙利"},{"iata":"MBA","lat":-4.0348300934,"lon":39.5942001343,"cca2":"KE","region":"非洲","city":"蒙巴萨","country_name":"肯尼亚"},{"iata":"YOW","lat":45.3224983215,"lon":-75.6691970825,"cca2":"CA","region":"北美洲","city":"渥太华","country_name":"加拿大"},{"iata":"UDI","lat":-18.8836116791,"lon":-48.225276947,"cca2":"BR","region":"南美洲","city":"乌贝兰迪亚","country_name":"巴西"},{"iata":"AUS","lat":30.1975,"lon":-97.6664,"cca2":"US","region":"北美洲","city":"奥斯汀","country_name":"美国"},{"iata":"LLK","lat":38.7463989258,"lon":48.8180007935,"cca2":"AZ","region":"中东","city":"阿斯塔拉","country_name":"阿塞拜疆"},{"iata":"BOS","lat":42.36429977,"lon":-71.00520325,"cca2":"US","region":"北美洲","city":"波士顿","country_name":"美国"},{"iata":"FIH","lat":-4.3857498169,"lon":15.4446001053,"cca2":"CD","region":"非洲","city":"金沙萨","country_name":"刚果（金）"},{"iata":"MAN","lat":53.3536987305,"lon":-2.2749500275,"cca2":"GB","region":"欧洲","city":"曼彻斯特","country_name":"英国"},{"iata":"TIA","lat":41.4146995544,"lon":19.7206001282,"cca2":"AL","region":"欧洲","city":"地拉那","country_name":"阿尔巴尼亚"},{"iata":"FLN","lat":-27.6702785492,"lon":-48.5525016785,"cca2":"BR","region":"南美洲","city":"弗洛里亚诺波利斯","country_name":"巴西"},{"iata":"EZE","lat":-34.8222,"lon":-58.5358,"cca2":"AR","region":"南美洲","city":"布宜诺斯艾利斯","country_name":"阿根廷"},{"iata":"PER","lat":-31.9402999878,"lon":115.967002869,"cca2":"AU","region":"大洋洲","city":"珀斯","country_name":"澳大利亚"},{"iata":"CDG","lat":49.0127983093,"lon":2.5499999523,"cca2":"FR","region":"欧洲","city":"巴黎","country_name":"法国"},{"iata":"YXE","lat":52.1707992554,"lon":-106.699996948,"cca2":"CA","region":"北美洲","city":"萨斯卡通","country_name":"加拿大"},{"iata":"BOD","lat":44.82946,"lon":-0.58355,"cca2":"FR","region":"欧洲","city":"波尔多","country_name":"法国"},{"iata":"TPA","lat":27.9755001068,"lon":-82.533203125,"cca2":"US","region":"北美洲","city":"坦帕","country_name":"美国"},{"iata":"CRK","lat":15.1859,"lon":120.5599,"cca2":"PH","region":"亚太地区","city":"打拉市","country_name":"菲律宾"},{"iata":"PHX","lat":33.434299469,"lon":-112.012001038,"cca2":"US","region":"北美洲","city":"菲尼克斯","country_name":"美国"},{"iata":"FSD","lat":43.540819819502,"lon":-96.65511577730963,"cca2":"US","region":"北美洲","city":"苏福尔斯","country_name":"美国"},{"iata":"JIB","lat":11.5473003387,"lon":43.1595001221,"cca2":"DJ","region":"非洲","city":"吉布提","country_name":"吉布提"},{"iata":"MCT","lat":23.5932998657,"lon":58.2844009399,"cca2":"OM","region":"中东","city":"马斯喀特","country_name":"阿曼"},{"iata":"ORN","lat":35.6911,"lon":-0.6416,"cca2":"DZ","region":"非洲","city":"奥兰","country_name":"阿尔及利亚"},{"iata":"MEX","lat":19.4363002777,"lon":-99.0720977783,"cca2":"MX","region":"北美洲","city":"墨西哥城","country_name":"墨西哥"},{"iata":"SKP","lat":41.9616012573,"lon":21.6214008331,"cca2":"MK","region":"欧洲","city":"斯科普里","country_name":"北马其顿"},{"iata":"LAX","lat":33.94250107,"lon":-118.4079971,"cca2":"US","region":"北美洲","city":"洛杉矶","country_name":"美国"},{"iata":"MDE","lat":6.16454,"lon":-75.4231,"cca2":"CO","region":"南美洲","city":"麦德林","country_name":"哥伦比亚"},{"iata":"PTY","lat":9.0713596344,"lon":-79.3834991455,"cca2":"PA","region":"南美洲","city":"巴拿马城","country_name":"巴拿马"},{"iata":"CZL","lat":36.335972,"lon":6.598562,"cca2":"DZ","region":"非洲","city":"君士坦丁","country_name":"阿尔及利亚"},{"iata":"BNU","lat":-26.89245,"lon":-49.07696,"cca2":"BR","region":"南美洲","city":"布卢梅瑙","country_name":"巴西"},{"iata":"GVA","lat":46.2380981445,"lon":6.1089501381,"cca2":"CH","region":"欧洲","city":"日内瓦","country_name":"瑞士"},{"iata":"PDX","lat":45.58869934,"lon":-122.5979996,"cca2":"US","region":"北美洲","city":"波特兰","country_name":"美国"},{"iata":"GND","lat":12.007116,"lon":-61.7882288,"cca2":"GD","region":"南美洲","city":"圣乔治","country_name":"格林纳达"},{"iata":"CKG","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"重庆","country_name":"中国"},{"iata":"XIY","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"宝鸡","country_name":"中国"},{"iata":"EBL","lat":36.1901,"lon":43.993,"cca2":"IQ","region":"中东","city":"埃尔比勒","country_name":"伊拉克"},{"iata":"CMB","lat":7.1807599068,"lon":79.8841018677,"cca2":"LK","region":"亚太地区","city":"科伦坡","country_name":"斯里兰卡"},{"iata":"RIC","lat":37.5051994324,"lon":-77.3197021484,"cca2":"US","region":"北美洲","city":"里士满","country_name":"美国"},{"iata":"BGI","lat":13.103562,"lon":-59.603226,"cca2":"BB","region":"北美洲","city":"布里奇敦","country_name":"巴巴多斯"},{"iata":"CGO","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"郑州","country_name":"中国"},{"iata":"TLV","lat":32.0113983154,"lon":34.8866996765,"cca2":"IL","region":"中东","city":"特拉维夫","country_name":"以色列"},{"iata":"GDL","lat":20.5217990875,"lon":-103.3109970093,"cca2":"MX","region":"北美洲","city":"瓜达拉哈拉","country_name":"墨西哥"},{"iata":"CMH","lat":39.9980010986,"lon":-82.8918991089,"cca2":"US","region":"北美洲","city":"哥伦布","country_name":"美国"},{"iata":"KBP","lat":50.3450012207,"lon":30.8946990967,"cca2":"UA","region":"欧洲","city":"基辅","country_name":"乌克兰"},{"iata":"KEF","lat":63.9850006104,"lon":-22.6056003571,"cca2":"IS","region":"欧洲","city":"雷克雅未克","country_name":"冰岛"},{"iata":"ABQ","lat":35.0844,"lon":-106.6504,"cca2":"US","region":"北美洲","city":"阿尔伯克基","country_name":"美国"},{"iata":"MAA","lat":12.9900054932,"lon":80.1692962646,"cca2":"IN","region":"亚太地区","city":"金奈","country_name":"印度"},{"iata":"PMO","lat":38.16114,"lon":13.31546,"cca2":"IT","region":"欧洲","city":"巴勒莫","country_name":"意大利"},{"iata":"QRO","lat":20.6173000336,"lon":-100.185997009,"cca2":"MX","region":"北美洲","city":"克雷塔罗","country_name":"墨西哥"},{"iata":"DKR","lat":14.7412099,"lon":-17.4889771,"cca2":"SN","region":"非洲","city":"达喀尔","country_name":"塞内加尔"},{"iata":"KTM","lat":27.6965999603,"lon":85.3591003418,"cca2":"NP","region":"亚太地区","city":"加德满都","country_name":"尼泊尔"},{"iata":"RIX","lat":56.9235992432,"lon":23.9710998535,"cca2":"LV","region":"欧洲","city":"里加","country_name":"拉脱维亚"},{"iata":"YVR","lat":49.193901062,"lon":-123.183998108,"cca2":"CA","region":"北美洲","city":"温哥华","country_name":"加拿大"},{"iata":"ANC","lat":61.158555,"lon":-149.890208,"cca2":"US","region":"北美洲","city":"安克雷奇","country_name":"美国"},{"iata":"CLO","lat":3.54322,"lon":-76.3816,"cca2":"CO","region":"南美洲","city":"卡利","country_name":"哥伦比亚"},{"iata":"CZX","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"常州","country_name":"中国"},{"iata":"NQZ","lat":51.167801,"lon":71.418893,"cca2":"KZ","region":"欧洲","city":"阿斯塔纳","country_name":"哈萨克斯坦"},{"iata":"HKG","lat":22.3089008331,"lon":113.915000916,"cca2":"HK","region":"亚太地区","city":"香港","country_name":"香港"},{"iata":"CGK","lat":-6.1275229,"lon":106.6515118,"cca2":"ID","region":"亚太地区","city":"雅加达","country_name":"印度尼西亚"},{"iata":"SFO","lat":37.6189994812,"lon":-122.375,"cca2":"US","region":"北美洲","city":"旧金山","country_name":"美国"},{"iata":"CGY","lat":8.4156198502,"lon":124.611000061,"cca2":"PH","region":"亚太地区","city":"卡加延-德奥罗","country_name":"菲律宾"},{"iata":"XNN","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"西宁","country_name":"中国"},{"iata":"ACC","lat":5.614818,"lon":-0.205874,"cca2":"GH","region":"非洲","city":"阿克拉","country_name":"加纳"},{"iata":"CFC","lat":-26.7762,"lon":-51.0125,"cca2":"BR","region":"南美洲","city":"卡萨多","country_name":"巴西"},{"iata":"JNB","lat":-26.133333,"lon":28.25,"cca2":"ZA","region":"非洲","city":"约翰内斯堡","country_name":"南非"},{"iata":"PRG","lat":50.1007995605,"lon":14.2600002289,"cca2":"CZ","region":"欧洲","city":"布拉格","country_name":"捷克"},{"iata":"ADD","lat":9.00005,"lon":38.78446,"cca2":"ET","region":"非洲","city":"亚的斯亚贝巴","country_name":"埃塞俄比亚"},{"iata":"SJP","lat":-20.807157,"lon":-49.378994,"cca2":"BR","region":"南美洲","city":"圣若泽杜里奥普雷图","country_name":"巴西"},{"iata":"PKX","lat":0,"lon":0,"cca2":"CN","region":"Asia","city":"廊坊","country_name":"中国"},{"iata":"BEG","lat":44.8184013367,"lon":20.3090991974,"cca2":"RS","region":"欧洲","city":"贝尔格莱德","country_name":"塞尔维亚"},{"iata":"SJC","lat":37.3625984192,"lon":-121.929000855,"cca2":"US","region":"北美洲","city":"圣何塞","country_name":"美国"},{"iata":"XAP","lat":-27.1341991425,"lon":-52.6566009521,"cca2":"BR","region":"南美洲","city":"沙佩科","country_name":"巴西"},{"iata":"KIX","lat":34.4272994995,"lon":135.244003296,"cca2":"JP","region":"亚太地区","city":"大阪","country_name":"日本"},{"iata":"PBH","lat":27.4712,"lon":89.6339,"cca2":"BT","region":"亚太地区","city":"廷布","country_name":"不丹"},{"iata":"LCA","lat":34.8750991821,"lon":33.6249008179,"cca2":"CY","region":"欧洲","city":"尼科西亚","country_name":"塞浦路斯"},{"iata":"MLA","lat":35.886054,"lon":14.47609,"cca2":"MT","region":"欧洲","city":"Santa Venera","country_name":"马耳他"},{"iata":"DTW","lat":42.2123985291,"lon":-83.3534011841,"cca2":"US","region":"北美洲","city":"底特律","country_name":"美国"},{"iata":"PEK","lat":40.0799,"lon":116.603,"cca2":"CN","region":"亚太地区","city":"北京","country_name":"中国"},{"iata":"PVG","lat":31.1443,"lon":121.808,"cca2":"CN","region":"亚太地区","city":"上海","country_name":"中国"},{"iata":"HGH","lat":30.2295,"lon":120.434,"cca2":"CN","region":"亚太地区","city":"杭州","country_name":"中国"},{"iata":"WUH","lat":30.7838,"lon":114.208,"cca2":"CN","region":"亚太地区","city":"武汉","country_name":"中国"},{"iata":"XIY","lat":34.4471,"lon":108.752,"cca2":"CN","region":"亚太地区","city":"西安","country_name":"中国"},{"iata":"CKG","lat":29.7192,"lon":106.642,"cca2":"CN","region":"亚太地区","city":"重庆","country_name":"中国"},{"iata":"KMG","lat":25.102,"lon":102.743,"cca2":"CN","region":"亚太地区","city":"昆明","country_name":"中国"},{"iata":"TAO","lat":36.2664,"lon":120.382,"cca2":"CN","region":"亚太地区","city":"青岛","country_name":"中国"},{"iata":"DLC","lat":38.9657,"lon":121.539,"cca2":"CN","region":"亚太地区","city":"大连","country_name":"中国"},{"iata":"XMN","lat":24.544,"lon":118.128,"cca2":"CN","region":"亚太地区","city":"厦门","country_name":"中国"},{"iata":"NKG","lat":31.742,"lon":118.862,"cca2":"CN","region":"亚太地区","city":"南京","country_name":"中国"},{"iata":"TSN","lat":39.1244,"lon":117.346,"cca2":"CN","region":"亚太地区","city":"天津","country_name":"中国"},{"iata":"HAK","lat":19.9349,"lon":110.459,"cca2":"CN","region":"亚太地区","city":"海口","country_name":"中国"},{"iata":"CGO","lat":34.5197,"lon":113.841,"cca2":"CN","region":"亚太地区","city":"郑州","country_name":"中国"},{"iata":"TNA","lat":36.8572,"lon":117.216,"cca2":"CN","region":"亚太地区","city":"济南","country_name":"中国"},{"iata":"HRB","lat":45.6234,"lon":126.25,"cca2":"CN","region":"亚太地区","city":"哈尔滨","country_name":"中国"},{"iata":"SHE","lat":41.6398,"lon":123.483,"cca2":"CN","region":"亚太地区","city":"沈阳","country_name":"中国"},{"iata":"URC","lat":43.9071,"lon":87.4742,"cca2":"CN","region":"亚太地区","city":"乌鲁木齐","country_name":"中国"},{"iata":"LHW","lat":36.5152,"lon":103.62,"cca2":"CN","region":"亚太地区","city":"兰州","country_name":"中国"},{"iata":"HND","lat":35.5523,"lon":139.78,"cca2":"JP","region":"亚太地区","city":"东京羽田","country_name":"日本"},{"iata":"KIX","lat":34.4273,"lon":135.244,"cca2":"JP","region":"亚太地区","city":"大阪","country_name":"日本"},{"iata":"NGO","lat":35.255,"lon":136.925,"cca2":"JP","region":"亚太地区","city":"名古屋","country_name":"日本"},{"iata":"CTS","lat":42.7752,"lon":141.692,"cca2":"JP","region":"亚太地区","city":"札幌","country_name":"日本"},{"iata":"PUS","lat":35.1796,"lon":128.938,"cca2":"KR","region":"亚太地区","city":"釜山","country_name":"韩国"},{"iata":"OKJ","lat":34.7569,"lon":133.856,"cca2":"JP","region":"亚太地区","city":"冈山","country_name":"日本"},{"iata":"KOJ","lat":31.8034,"lon":130.719,"cca2":"JP","region":"亚太地区","city":"鹿儿岛","country_name":"日本"},{"iata":"SDJ","lat":38.1397,"lon":140.917,"cca2":"JP","region":"亚太地区","city":"仙台","country_name":"日本"},{"iata":"HIJ","lat":34.4361,"lon":132.919,"cca2":"JP","region":"亚太地区","city":"广岛","country_name":"日本"},{"iata":"KMJ","lat":32.8373,"lon":130.855,"cca2":"JP","region":"亚太地区","city":"熊本","country_name":"日本"},{"iata":"KMQ","lat":36.3948,"lon":136.408,"cca2":"JP","region":"亚太地区","city":"小松","country_name":"日本"},{"iata":"AOJ","lat":40.7347,"lon":140.691,"cca2":"JP","region":"亚太地区","city":"青森","country_name":"日本"},{"iata":"GAJ","lat":38.4119,"lon":140.371,"cca2":"JP","region":"亚太地区","city":"山形","country_name":"日本"},{"iata":"IBR","lat":36.1816,"lon":140.415,"cca2":"JP","region":"亚太地区","city":"茨城","country_name":"日本"},{"iata":"UBJ","lat":33.9303,"lon":131.279,"cca2":"JP","region":"亚太地区","city":"山口宇部","country_name":"日本"},{"iata":"TAK","lat":34.2142,"lon":134.016,"cca2":"JP","region":"亚太地区","city":"高松","country_name":"日本"},{"iata":"MYJ","lat":33.8272,"lon":132.7,"cca2":"JP","region":"亚太地区","city":"松山","country_name":"日本"},{"iata":"IZO","lat":35.4135,"lon":132.89,"cca2":"JP","region":"亚太地区","city":"出云","country_name":"日本"},{"iata":"YGJ","lat":35.4922,"lon":133.236,"cca2":"JP","region":"亚太地区","city":"米子","country_name":"日本"}]`
	var locations []location

	// 1. 尝试解析内置数据
	if body != `` {
		if err := json.Unmarshal([]byte(body), &locations); err != nil {
			fmt.Printf("解析内置位置数据失败: %v,尝试加载 locations.json\n", err)
			locations = nil // 清空 locations,确保从文件加载时不会混淆
		} else {
			fmt.Println("成功解析内置位置数据")
		}
	}

	// 2. 如果内置数据解析失败或 body 为空,尝试从文件加载
	if len(locations) == 0 {
		locationsData, err := os.ReadFile("locations.json")
		if err != nil {
			fmt.Printf("读取 locations.json 失败: %v\n", err)
			if *telegramToken != "" && *telegramChatID != "" {
				sendTelegramMessage("*⚠️ 错误*\n无法加载位置数据: " + escapeMarkdownV2(err.Error()))
				sendTelegramMessage("*🎉 程序运行结束*")
			}
			os.Exit(1)
		}
		
		// 重新解析,确保 locations 变量被正确填充
		if err := json.Unmarshal(locationsData, &locations); err != nil {
			fmt.Printf("解析 locations.json 失败: %v\n", err)
			if *telegramToken != "" && *telegramChatID != "" {
				sendTelegramMessage("*⚠️ 错误*\n解析 locations.json 失败: " + escapeMarkdownV2(err.Error()))
				sendTelegramMessage("*🎉 程序运行结束*")
			}
			os.Exit(1)
		}
		fmt.Println("成功加载 locations.json")
	}

	// 3. 统一将 locations 切片转换为 locationMap (确保在任何调用前执行)
	if len(locations) == 0 {
		locationMap = make(map[string]location)
		fmt.Println("警告：未找到任何位置数据，位置信息将无法显示。")
	} else {
		locationMap = make(map[string]location)
		for _, loc := range locations {
			locationMap[loc.Iata] = loc
		}
		fmt.Printf("位置数据加载完成，共 %d 条记录。\n", len(locationMap))
	}
    // --- 位置数据加载逻辑修正结束 ---
	
	if *cidrPorts != "" && *asn == "" {
		// 验证 CIDR 文件是否存在
		if _, err := os.Stat(*cidrFile); os.IsNotExist(err) {
			fmt.Printf("[错误] CIDR 文件 %s 不存在\n", *cidrFile)
			if *telegramToken != "" && *telegramChatID != "" {
				sendTelegramMessage("*⚠️ 错误*\n" + escapeMarkdownV2(fmt.Sprintf("CIDR 文件 %s 不存在", *cidrFile)))
				sendTelegramMessage("*🎉 程序运行结束*")
			}
			os.Exit(1)
		}
		// 执行 CIDR 扫描并写入 ip.txt
		processCIDRAndPorts(locationMap) // 这里的 locationMap 现在是填充好的
		fmt.Println("CIDR 展开和端口检测完成,写入 ip.txt")
		if !*cidrSpeedTest {
			fmt.Println("未启用测速,程序退出")
			if *telegramToken != "" && *telegramChatID != "" {
				sendTelegramMessage("*🎉 CIDR 扫描结束*")
			}
			return
		}
	}

	if *cidrSpeedTest && *cidrPorts == "" && *asn == "" {
		fmt.Println("[信息] -cidr-speedtest 启用,但 -cidr-ports 和 -asn 为空,跳过 CIDR 扫描")
	}

	if _, err := os.Stat(*File); os.IsNotExist(err) {
		fmt.Printf("[错误] 输入文件 %s 不存在\n", *File)
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage("*⚠️ 错误*\n" + escapeMarkdownV2(fmt.Sprintf("输入文件 %s 不存在", *File)))
			sendTelegramMessage("*🎉 程序运行结束*")
		}
		os.Exit(1)
	}

	// 捕获 panic 并通过 Telegram 通知
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "程序崩溃: %v\n", r)
			if *telegramToken != "" && *telegramChatID != "" {
				sendTelegramMessage(fmt.Sprintf("*⚠️ 错误*\n程序崩溃: %s", escapeMarkdownV2(fmt.Sprintf("%v", r))))
				sendTelegramMessage("*🎉 程序运行结束*")
			}
			os.Exit(1)
		}
	}()

	// 发送启动消息
	if *telegramToken != "" && *telegramChatID != "" {
		sendTelegramMessage("*🚀 开始延迟/速度测试*")
	}

	// 如果仅提供 -asn,下载 CIDR 列表并退出
	if *asn != "" && *cidrPorts == "" && !*cidrSpeedTest {
		downloadCIDRFromASN(*asn)
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage("*✅ 成功*\nCIDR 列表已下载到 `cidr.txt`")
			sendTelegramMessage("*🎉 程序运行结束*")
		}
		return
	}

	// 如果提供 -asn 和 -cidr-ports,执行 CIDR 扫描并写入 ip.txt
	if *cidrPorts != "" && *asn != "" {
		downloadCIDRFromASN(*asn)
		processCIDRAndPorts(locationMap) // 这里的 locationMap 也是填充好的
		fmt.Println("CIDR 展开和端口检测完成,写入 ip.txt")
		if !*cidrSpeedTest {
			fmt.Println("未启用测速,程序退出")
			if *telegramToken != "" && *telegramChatID != "" {
				sendTelegramMessage("*🎉 CIDR 扫描结束*")
			}
			return
		}
	}

	// 测速逻辑(包括延迟测试)
	startTime := time.Now()

	// 读取 ip.txt
	ipPorts, err := readIPs(*File)
	if err != nil {
		fmt.Printf("读取 IP 文件失败: %v\n", err)
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage("*⚠️ 错误*\n读取 IP 文件失败: " + escapeMarkdownV2(err.Error()))
			sendTelegramMessage("*🎉 程序运行结束*")
		}
		os.Exit(1)
	}
	fmt.Printf("共读取到 %d 个 IP:端口对\n", len(ipPorts))

	// 如果启用随机扫描,打乱IP顺序
	if *randomizeHosts {
		fmt.Println("随机打乱扫描顺序已启用,正在打乱IP列表...")
		shuffleStrings(ipPorts)
		fmt.Println("IP列表已随机打乱")
	}

	// 有效 IP 检测和延迟测试
	var wg sync.WaitGroup
	wg.Add(len(ipPorts))
	resultChan := make(chan result, len(ipPorts))
	semaphore := make(chan struct{}, *maxThreads)
	var count int
	total := len(ipPorts)
	var printMu sync.Mutex

	for _, ip := range ipPorts {
		semaphore <- struct{}{}
		go func(ip string) {
			defer func() {
				<-semaphore
				wg.Done()
				count++
				percentage := float64(count) / float64(total) * 100
				printMu.Lock()
				fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\r", count, total, percentage)
				if count == total {
					fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\n", count, total, percentage)
				}
				printMu.Unlock()
			}()

			parts := strings.Fields(ip)
			if len(parts) != 2 {
				printMu.Lock()
				fmt.Printf("IP地址格式错误: %s\n", ip)
				printMu.Unlock()
				return
			}
			ipAddr := parts[0]
			portStr := parts[1]

			port, err := strconv.Atoi(portStr)
			if err != nil {
				printMu.Lock()
				fmt.Printf("端口格式错误: %s\n", portStr)
				printMu.Unlock()
				return
			}

			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: 0,
			}
			start := time.Now()
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ipAddr, strconv.Itoa(port)))
			if err != nil {
				return
			}
			defer func(conn net.Conn) {
				err := conn.Close()
				if err != nil {
				}
			}(conn)

			tcpDuration := time.Since(start)
			start = time.Now()

			client := http.Client{
				Transport: &http.Transport{
					Dial: func(network, addr string) (net.Conn, error) {
						return conn, nil
					},
				},
				Timeout: timeout,
			}

			var protocol string
			if *enableTLS {
				protocol = "https://"
			} else {
				protocol = "http://"
			}
			requestURL := protocol + *TCPurl + "/cdn-cgi/trace"

			req, _ := http.NewRequest("GET", requestURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Close = true
			resp, err := client.Do(req)
			if err != nil {
				return
			}

			duration := time.Since(start)
			if duration > maxDuration {
				return
			}

			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
				}
			}(resp.Body)
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			if strings.Contains(string(body), "uag=Mozilla/5.0") {
				if matches := regexp.MustCompile(`colo=([A-Z]+)`).FindStringSubmatch(string(body)); len(matches) > 1 {
					dataCenter := matches[1]
					
					// *** 替换原有的两个 fmt.Printf/printMu 块，使用统一函数 ***
					// 注意：这里需要确保 locationMap 在当前作用域可用
					printValidIP(ipAddr, port, dataCenter, tcpDuration, locationMap, &printMu)

					loc, ok := locationMap[dataCenter]
					// 保持原来的 resultChan 填充逻辑（一字不改）
					if ok {
						// 原有 printMu.Lock()/Unlock() 和 fmt.Printf 已移除
						resultChan <- result{
							ip:          ipAddr,
							port:        port,
							dataCenter:  dataCenter,
							region:      loc.Region,
							cca2:        loc.Cca2,
							cca1:        loc.Cca1,
							countryName: loc.CountryName,
							city:        loc.City,
							latency:     fmt.Sprintf("%d ms", tcpDuration.Milliseconds()),
							tcpDuration: tcpDuration,
						}
					} else {
						// 原有 printMu.Lock()/Unlock() 和 fmt.Printf 已移除
						resultChan <- result{
							ip:          ipAddr,
							port:        port,
							dataCenter:  dataCenter,
							region:      "",
							cca2:        "",
							cca1:        "",
							countryName: "",
							city:        "",
							latency:     fmt.Sprintf("%d ms", tcpDuration.Milliseconds()),
							tcpDuration: tcpDuration,
						}
					}
				}
			}
		}(ip)
	}

	wg.Wait()
	close(resultChan)

	// 下载速度测试 - 修复2：CSV写入添加去重
	var csvResults []speedtestresult
	seenResults := make(map[string]bool)  // 添加去重map
	var csvMu sync.Mutex  // 保护csvResults和seenResults
	var completed int64  // 【新增】测速进度原子计数器
	
	if *speedTest > 0 && len(resultChan) > 0 {
		fmt.Printf("开始测速\n")
		var wg2 sync.WaitGroup
		wg2.Add(*speedTest)
		count = 0
		total = len(resultChan)
		csvResults = []speedtestresult{}
		for i := 0; i < *speedTest; i++ {
			semaphore <- struct{}{}
			go func() {
				defer func() {
					<-semaphore
					wg2.Done()
					
					// 【新增】原子操作获取当前计数
					newCount := atomic.AddInt64(&completed, 1)
					percentage := float64(newCount) / float64(total) * 100
					
					// 【新增】计算并显示 ETA（每5个或最后更新）
					if newCount % 5 == 0 || newCount >= int64(total) {
						elapsed := time.Since(startTime)
						var etaStr string
						if newCount > 0 && elapsed.Seconds() > 1 {
							rate := float64(newCount) / elapsed.Seconds()
							remaining := float64(total - int(newCount))
							etaSeconds := remaining / rate
							etaDuration := time.Duration(etaSeconds * float64(time.Second))
							
							etaHours := int(etaDuration.Hours())
							etaMinutes := int(etaDuration.Minutes()) % 60
							etaSecondsInt := int(etaDuration.Seconds()) % 60
							
							if etaHours > 0 {
								etaStr = fmt.Sprintf("%02d小时 %02d分 %02d秒", etaHours, etaMinutes, etaSecondsInt)
							} else if etaMinutes > 0 {
								etaStr = fmt.Sprintf("%02d分 %02d秒", etaMinutes, etaSecondsInt)
							} else {
								etaStr = fmt.Sprintf("%d秒", etaSecondsInt)
							}
							
							safePrintProgress(fmt.Sprintf("测速进度: %d/%d (%.2f%%) 预计剩余耗时: %s",
								newCount, total, percentage, etaStr))
						} else {
							safePrintProgress(fmt.Sprintf("测速进度: %d/%d (%.2f%%) 预计剩余耗时: 计算中...", 
								newCount, total, percentage))
						}
					}
					
					printMu.Lock()
					if newCount >= int64(total) {
						fmt.Printf("\n")
					}
					printMu.Unlock()
				}()
				
				// 【关键】恢复原来的测速循环代码
				for res := range resultChan {
					downloadSpeed := getDownloadSpeed(res.ip, res.port)
					
					if downloadSpeed >= float64(*speedLimit) {
						csvMu.Lock()
						key := fmt.Sprintf("%s:%d", res.ip, res.port)
						if !seenResults[key] {
							seenResults[key] = true
							csvResults = append(csvResults, speedtestresult{result: res, downloadSpeed: downloadSpeed})
						}
						csvMu.Unlock()
					}
				}
			}()
		}
		wg2.Wait()
	} else {
		for res := range resultChan {
			csvMu.Lock()
			key := fmt.Sprintf("%s:%d", res.ip, res.port)
			if !seenResults[key] {
				seenResults[key] = true
				csvResults = append(csvResults, speedtestresult{result: res})
			}
			csvMu.Unlock()
		}
	}

	// 生成 CSV 输出
	if len(csvResults) > 0 {
		file, err := os.Create(*outFile)
		if err != nil {
			fmt.Printf("创建测速结果文件失败: %v\n", err)
			if *telegramToken != "" && *telegramChatID != "" {
				sendTelegramMessage("*⚠️ 错误*\n创建测速结果文件失败: " + escapeMarkdownV2(err.Error()))
				sendTelegramMessage("*🎉 程序运行结束*")
			}
			os.Exit(1)
		}
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
			}
		}(file) // <-- 1. defer 匿名函数在此结束
		
		writer := csv.NewWriter(file)
		defer writer.Flush()
		// CSV 表头：移除"中文国家名称"，保持"下载速度MB/s"
		header := []string{"IP地址", "端口", "TLS", "数据中心", "地区", "国家代码", "国家", "城市", "网络延迟", "下载速度MB/s"}
		if err := writer.Write(header); err != nil {
			fmt.Printf("写入测速 CSV 表头失败: %v\n", err)
			if *telegramToken != "" && *telegramChatID != "" {
				sendTelegramMessage("*⚠️ 错误*\n写入测速 CSV 表头失败: " + escapeMarkdownV2(err.Error()))
				sendTelegramMessage("*🎉 程序运行结束*")
			}
			os.Exit(1)
		}

		if *speedTest > 0 {
			sort.Slice(csvResults, func(i, j int) bool {
				return csvResults[i].downloadSpeed > csvResults[j].downloadSpeed
			})
		} else {
			sort.Slice(csvResults, func(i, j int) bool {
				return csvResults[i].result.tcpDuration < csvResults[j].result.tcpDuration
			})
		}

		for i, res := range csvResults {
			// CSV 记录：修正国际代码为 cca2，国家为 countryName，下载速度添加 MB 单位
			record := []string{
				res.result.ip,
				strconv.Itoa(res.result.port),
				strings.ToUpper(strconv.FormatBool(*enableTLS)),
				res.result.dataCenter,
				res.result.region,
				res.result.cca2, // 国际代码使用 cca2
				res.result.countryName, // 国家使用 countryName
				res.result.city,
				res.result.latency,
			}
			if *speedTest > 0 {
				record = append(record, fmt.Sprintf("%.2f MB", res.downloadSpeed)) // 下载速度添加 MB 单位
			}
			if err := writer.Write(record); err != nil {
				fmt.Printf("写入测速 CSV 记录失败(第 %d 条): %v\n", i+1, err)
				if *telegramToken != "" && *telegramChatID != "" {
					sendTelegramMessage(fmt.Sprintf("*⚠️ 错误*\n写入测速 CSV 记录失败(第 %d 条): %s", i+1, escapeMarkdownV2(err.Error())))
					sendTelegramMessage("*🎉 程序运行结束*")
				}
				os.Exit(1)
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			fmt.Printf("写入测速 CSV 时发生错误: %v\n", err)
			if *telegramToken != "" && *telegramChatID != "" {
				sendTelegramMessage("*⚠️ 错误*\n写入测速 CSV 时发生错误: " + escapeMarkdownV2(err.Error()))
				sendTelegramMessage("*🎉 程序运行结束*")
			}
			os.Exit(1)
		}
		fmt.Printf("测试结果文件生成完成: %s\n", *outFile)
	} else {
		fmt.Println("无满足速度要求的 IP,跳过生成测速结果文件")
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage("*⚠️ 无满足速度要求的 IP*\n测速未生成结果文件")
		}
	}

	// 生成检测报告
	var report strings.Builder
	duration := time.Since(startTime)
	hours := int(duration.Hours())
	minutes := int(duration.Minutes()) % 60
	seconds := int(duration.Seconds()) % 60

	if len(csvResults) > 0 {
		cstZone := time.FixedZone("CST", 8*3600)
		startTime = startTime.In(cstZone)
		duration := time.Since(startTime)
		hours = int(duration.Hours())
		minutes = int(duration.Minutes()) % 60
		seconds = int(duration.Seconds()) % 60

		countryCount := make(map[string]int)
		for _, res := range csvResults {
			cca2 := res.result.cca2
			if cca2 == "" || cca2 == "未知" {
				cca2 = "UNKNOWN"
			}
			countryCount[cca2]++
		}
		var countries []string
		for cca2 := range countryCount {
			countries = append(countries, cca2)
		}
		sort.Strings(countries)

		var totalLatency float64
		var minLatency, maxLatency float64
		if len(csvResults) > 0 {
			minLatency = float64(csvResults[0].result.tcpDuration.Milliseconds())
			maxLatency = minLatency
			for _, res := range csvResults {
				latencyMs := float64(res.result.tcpDuration.Milliseconds())
				totalLatency += latencyMs
				if latencyMs < minLatency {
					minLatency = latencyMs
				}
				if latencyMs > maxLatency {
					maxLatency = latencyMs
				}
			}
		}
		avgLatency := 0.0
		if len(csvResults) > 0 {
			avgLatency = totalLatency / float64(len(csvResults))
		}

		var avgSpeed, minSpeed, maxSpeed float64
		if len(csvResults) > 0 && *speedTest > 0 {
			for _, res := range csvResults {
				avgSpeed += res.downloadSpeed
				if minSpeed == 0 || res.downloadSpeed < minSpeed {
					minSpeed = res.downloadSpeed
				}
				if res.downloadSpeed > maxSpeed {
					maxSpeed = res.downloadSpeed
				}
			}
			avgSpeed /= float64(len(csvResults))
		} else {
			avgSpeed, minSpeed, maxSpeed = 0, 0, 0
		}

		fmt.Fprintf(&report, "*✅ 延迟/速度测试完成*\n")
		fmt.Fprintf(&report, "⏰ 运行耗时: %02d时 %02d分 %02d秒\n", hours, minutes, seconds)
		fmt.Fprintf(&report, "  - 总计测试IP: %d\n", len(ipPorts))
		fmt.Fprintf(&report, "  - 有效IP: %d\n", len(csvResults))
		fmt.Fprintf(&report, "*🌍 国家分布*\n")
		for _, cca2 := range countries {
			fmt.Fprintf(&report, "- %s %s (%d个)\n", getCountryFlag(cca2), cca2, countryCount[cca2])
		}
		fmt.Fprintf(&report, "*📈 延迟统计*\n")
		fmt.Fprintf(&report, "  - 均值: %.2fms\n", avgLatency)
		fmt.Fprintf(&report, "  - 最低: %.2fms\n", minLatency)
		fmt.Fprintf(&report, "  - 最高: %.2fms\n", maxLatency)
		fmt.Fprintf(&report, "*⚡️ 速度统计*\n")
		if len(csvResults) > 0 && *speedTest > 0 {
			fmt.Fprintf(&report, "  - 均值: %.2f MB/s\n", avgSpeed)
			fmt.Fprintf(&report, "  - 最高: %.2f MB/s\n", maxSpeed)
			fmt.Fprintf(&report, "  - 最低: %.2f MB/s\n", minSpeed)
		} else {
			fmt.Fprintf(&report, "  - 均值: 待测\n")
			fmt.Fprintf(&report, "  - 最高: 待测\n")
			fmt.Fprintf(&report, "  - 最低: 待测\n")
		}
	} else {
		fmt.Fprintf(&report, "*⚠️ 无检测结果*\n")
		fmt.Fprintf(&report, "⏰ 运行耗时: %02d时 %02d分 %02d秒\n", hours, minutes, seconds)
		fmt.Fprintf(&report, "  - 总计测试IP: %d\n", len(ipPorts))
		fmt.Fprintf(&report, "  - 有效IP: 0\n")
	}

	fmt.Println("生成检测报告:\n" + report.String())
	if *telegramToken != "" && *telegramChatID != "" {
		sendTelegramMessage(report.String())
		// 推送 result.csv(仅一次)
		fileInfo, err := os.Stat(*outFile)
		if err == nil && fileInfo.Size() > 0 {
			sendTelegramFile(*outFile)
		} else {
			fmt.Printf("测试结果文件 %s 不存在或为空\n", *outFile)
			sendTelegramMessage(fmt.Sprintf("*⚠️ 错误*\n测试结果文件 `%s` 不存在或为空", escapeMarkdownV2(*outFile)))
		}
		sendTelegramMessage("*🎉 程序运行结束*")
	}
}

// scanCIDRPortsAndCollectValidIPs 处理CIDR列表展开、端口扫描、Cloudflare有效IP检测
// 功能详解:
// 1. 读取 cidr.txt 中的CIDR段
// 2. 排除 -exclude-ports 指定端口
// 3. 将大CIDR自动分割为 /24 (IPv4) 或 /64 (IPv6) 子网
// 4. 高并发（-max 或 -rate 控制）扫描所有 IP:端口 对
// 5. 使用 isOpenAndCloudflare 检测端口开放 + Cloudflare 服务
// 6. 实时固定底部进度条 + ETA
// 7. 发现有效IP立即打印（上部滚动日志）+ 强制刷新底部进度条（永不闪烁）
// 8. 扫描结束自动写入 ip.txt + Telegram 推送报告
// 9. 支持 -rate 速率限制 + Telegram 实时通知
// 10. 支持 -randomize-hosts 随机打乱扫描顺序（默认启用）
// 11. 【增强】支持大CIDR内存保护，超过阈值自动切换流式处理
func processCIDRAndPorts(locationMap map[string]location) {
	// 加载东八区时区
	cstZone := time.FixedZone("CST", 8*3600) // UTC+8,偏移量以秒为单位(8小时 * 3600秒/小时)

	startTime := time.Now().In(cstZone) // 使用东八区时间
	fmt.Printf("扫描CIDR, 开始计时:%s\n", startTime.Format("2006/01/02 15:04:05"))
	if *telegramToken != "" && *telegramChatID != "" {
		sendTelegramMessage(fmt.Sprintf("*📡 扫描CIDR开始*\n开始时间: `%s`", startTime.Format("2006/01/02 15:04:05")))
	}

	// 读取CIDR列表
	cidrs, err := readCIDRs(*cidrFile)
	if err != nil {
		fmt.Printf("读取CIDR文件失败: %v\n", err)
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage("*⚠️ 错误*\n读取CIDR文件失败: " + escapeMarkdownV2(err.Error()))
		}
		return
	}

	// 解析端口列表
	ports := parsePorts(*cidrPorts)
	if len(ports) == 0 {
		fmt.Println("[错误] 未指定有效端口")
		return
	}

	// 解析排除端口列表并进行过滤
	excludeList := parsePorts(*excludePorts)
	excludeMap := make(map[int]bool)
	for _, p := range excludeList {
		excludeMap[p] = true
	}
	var filteredPorts []int
	for _, p := range ports {
		if !excludeMap[p] {
			filteredPorts = append(filteredPorts, p)
		}
	}
	ports = filteredPorts // 更新为过滤后的端口列表

	var validIPs []string
	var mu sync.Mutex // 保护 validIPs
	var wg sync.WaitGroup
	
	// 修复1：CIDR扫描添加去重（防止CIDR重叠）
	seen := make(map[string]bool)
	var seenMu sync.Mutex  // 保护seen map
	
	// 确定并发数: 如果 rateLimit > 0, 则使用 rateLimit，否则使用 maxThreads
	var concurrency int
	if rateLimit.value > 0 {
		concurrency = rateLimit.value
	} else {
		concurrency = *maxThreads
	}
	// 使用协程池控制并发
	thread := make(chan struct{}, concurrency)
	
	// 设置速率限制器
	var limiter *rate.Limiter
	if rateLimit.value > 0 {
		limiter = rate.NewLimiter(rate.Limit(rateLimit.value), rateLimit.value)
	}

	// ========== 智能目标收集：先估算数量，决定是否预收集 ==========
	estimatedTargets := estimateTotalTargets(cidrs, ports)
	fmt.Printf("预估扫描目标数: %d (内存保护阈值: %d)\n", estimatedTargets, maxPreCollectTargets)

	var useStreamingMode bool
	if estimatedTargets > maxPreCollectTargets {
		useStreamingMode = true
		fmt.Printf("⚠️ 目标数量超过内存保护阈值，启用流式处理模式（内存友好）\n")
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage(fmt.Sprintf("*⚠️ 大CIDR警告*\n目标数 %d 超过阈值 %d，启用流式处理", estimatedTargets, maxPreCollectTargets))
		}
	} else {
		useStreamingMode = false
		fmt.Printf("✅ 目标数量在内存保护范围内，启用预收集随机模式（速度优先）\n")
	}

	var targets []scanTarget
	var total int64

	if !useStreamingMode {
		// ========== 模式A：预收集所有目标（版本2原版逻辑，带内存保护） ==========
		for _, cidrStr := range cidrs {
			subnets, err := splitCIDR(cidrStr)
			if err != nil {
				fmt.Printf("分割 CIDR %s 失败: %v\n", cidrStr, err)
				continue
			}
			for _, subnet := range subnets {
				expandCIDR(subnet.String(), func(ip string) {
					for _, port := range ports {
						targets = append(targets, scanTarget{ip: ip, port: port})
					}
				})
			}
		}

		// 🔀 关键修改：随机打乱扫描顺序（如果启用）
		if *randomizeHosts {
			rand.Shuffle(len(targets), func(i, j int) {
				targets[i], targets[j] = targets[j], targets[i]
			})
			fmt.Printf("已启用随机化扫描，共 %d 个目标\n", len(targets))
			if *telegramToken != "" && *telegramChatID != "" {
				sendTelegramMessage(fmt.Sprintf("*🔀 随机化扫描*\n已打乱 %d 个目标的扫描顺序", len(targets)))
			}
		} else {
			fmt.Printf("使用顺序扫描，共 %d 个目标\n", len(targets))
		}

		total = int64(len(targets))
	} else {
		// ========== 模式B：流式处理（版本1逻辑，大CIDR保护） ==========
		// 如果启用随机扫描,打乱CIDR顺序
		if *randomizeHosts {
			fmt.Println("随机打乱扫描顺序已启用,正在打乱CIDR列表...")
			shuffleStrings(cidrs)
			fmt.Println("CIDR列表已随机打乱")
		}

		// 如果启用随机扫描,打乱端口顺序
		if *randomizeHosts {
			shuffleIntegers(ports)
		}

		// 计算总任务数
		total = int64(estimatedTargets)
	}

	if total == 0 {
		fmt.Println("[信息] 没有可扫描的 IP:端口 对")
		return
	}

	var completed int64 // 原子计数器
	var printMu sync.Mutex // 保护终端打印操作
	var once sync.Once     // 用于确保 done 通道只关闭一次

	// 定时刷新进度
	ticker := time.NewTicker(200 * time.Millisecond) // 提高刷新频率
	defer ticker.Stop()
	done := make(chan struct{}) // 用于通知定时器停止
	go func() {
		for {
			select {
			case <-ticker.C:
				printMu.Lock()
				
				// **内联 printProgress 逻辑**
				completedVal := atomic.LoadInt64(&completed)
				percentage := 0.0
				if total > 0 {
					percentage = float64(completedVal) / float64(total) * 100.0
				}
				elapsed := time.Since(startTime)
				var etaStr string
				if completedVal == 0 || elapsed.Seconds() < 1 {
					etaStr = "计算中..."
				} else if completedVal >= total {
					etaStr = "0秒"
				} else {
					rate := float64(completedVal) / elapsed.Seconds()
					remaining := float64(total - completedVal)
					etaSeconds := remaining / rate
					etaDuration := time.Duration(etaSeconds * float64(time.Second))
					
					etaHours := int(etaDuration.Hours())
					etaMinutes := int(etaDuration.Minutes()) % 60
					etaSecondsInt := int(etaDuration.Seconds()) % 60
					
					// 修正后的 ETA 格式化逻辑
					if etaHours > 0 {
						etaStr = fmt.Sprintf("%02d小时 %02d分 %02d秒", etaHours, etaMinutes, etaSecondsInt)
					} else if etaMinutes > 0 {
						etaStr = fmt.Sprintf("%02d分 %02d秒", etaMinutes, etaSecondsInt)
					} else {
						etaStr = fmt.Sprintf("%d秒", etaSecondsInt)
					}
				}
				// 打印进度条（使用 \r 实现不换行刷新）
				safePrintProgress(fmt.Sprintf(
                    "扫描CIDR获取有效IP: %d/%d (%.2f%%) 预计剩余耗时: %s",
                    completedVal, total, percentage, etaStr,
                ))


				// **内联 printProgress 逻辑结束**

				printMu.Unlock()
			case <-done:
				// 扫描结束：打印最终进度
				printMu.Lock()
				// **内联 clearLine 逻辑**
				fmt.Print("\r\033[2K") 
				// **内联 clearLine 逻辑结束**
				
				// 🚨 最终修正：移除 '预计剩余耗时'，避免与主循环的最后一次输出冲突。
				fmt.Printf("扫描CIDR获取有效IP: %d/%d (100.00%%) 已完成\n", total, total)
				printMu.Unlock()
				return
			}
		}
	}()

	if !useStreamingMode {
		// ========== 模式A执行：预收集目标扫描 ==========
		for _, target := range targets {
			ip := target.ip
			port := target.port
			
			// 速率限制检查
			if limiter != nil {
				ctx := context.Background()
				if err := limiter.Wait(ctx); err != nil {
					fmt.Printf("速率限制器错误: %v\n", err)
					continue
				}
			}
			
			// 延迟抖动（如果启用）
			if *scanDelay > 0 || *delayJitter > 0 {
				delay := time.Duration(*scanDelay) * time.Millisecond
				if *delayJitter > 0 {
					jitter := time.Duration(rand.Intn(*delayJitter)) * time.Millisecond
					delay += jitter
				}
				time.Sleep(delay)
			}
			
			wg.Add(1)
			thread <- struct{}{} // 占用一个并发槽位
			go func(ip string, port int) {
				defer func() {
					<-thread // 释放一个并发槽位
					wg.Done()
					
					// 任务完成后更新进度
					newCompleted := atomic.AddInt64(&completed, 1)
					// 如果所有任务完成，关闭 done 通道
					if newCompleted >= total {
						once.Do(func() {
							close(done) 
						})
					}
				}()
				
				// 扫描和检测 Cloudflare 服务
				if ok, dataCenter, tcpDuration := isOpenAndCloudflare(ip, port); ok {
					// 修复1：添加IP去重检查
					key := fmt.Sprintf("%s:%d", ip, port)
					
					seenMu.Lock()
					if seen[key] {
						seenMu.Unlock()
						return  // 已存在，跳过
					}
					seen[key] = true
					seenMu.Unlock()
					
					mu.Lock()
					validIPs = append(validIPs, fmt.Sprintf("%s %d", ip, port))
					mu.Unlock()
					
					dataCenterStr := dataCenter
					if dataCenterStr == "" {
						dataCenterStr = "未知"
					}
					
					// **修复：正确的打印顺序以防止进度条闪烁**
					printMu.Lock()
					// 1. 清除当前进度条行
					// **内联 clearLine 逻辑**
					fmt.Print("\r\033[2K") 
					// **内联 clearLine 逻辑结束**
					
					// 2. 打印发现消息 (自动换行，成为日志滚动部分)
					// 🚨 修正：统一使用 &printMu 作为打印锁
					printValidIP(ip, port, dataCenter, tcpDuration, locationMap, &printMu)
					
					// 3. 重新绘制进度条到新的底部行
					// **内联 printProgress 逻辑**
					completedVal := atomic.LoadInt64(&completed)
					percentage := 0.0
					if total > 0 {
						percentage = float64(completedVal) / float64(total) * 100.0
					}
					elapsed := time.Since(startTime)
					var etaStr string
					if completedVal == 0 || elapsed.Seconds() < 1 {
						etaStr = "计算中..."
					} else if completedVal >= total {
						etaStr = "0秒"
					} else {
						rate := float64(completedVal) / elapsed.Seconds()
						remaining := float64(total - completedVal)
						etaSeconds := remaining / rate
						etaDuration := time.Duration(etaSeconds * float64(time.Second))
						
						etaHours := int(etaDuration.Hours())
						etaMinutes := int(etaDuration.Minutes()) % 60
						etaSecondsInt := int(etaDuration.Seconds()) % 60
						
						// 修正后的 ETA 格式化逻辑
						if etaHours > 0 {
							etaStr = fmt.Sprintf("%02d小时 %02d分 %02d秒", etaHours, etaMinutes, etaSecondsInt)
						} else if etaMinutes > 0 {
							etaStr = fmt.Sprintf("%02d分 %02d秒", etaMinutes, etaSecondsInt)
						} else {
							etaStr = fmt.Sprintf("%d秒", etaSecondsInt)
						}
					}
					safePrintProgress(fmt.Sprintf(
                        "扫描CIDR获取有效IP: %d/%d (%.2f%%) 预计剩余耗时: %s",
                        completedVal, total, percentage, etaStr,
                    ))

					// **内联 printProgress 逻辑结束**

					printMu.Unlock()
				}
			}(ip, port)
		}
	} else {
		// ========== 模式B执行：流式处理（大CIDR保护） ==========
		// 遍历CIDR
		for _, cidrStr := range cidrs {
			// 分割大 CIDR
			subnets, err := splitCIDR(cidrStr)
			if err != nil {
				fmt.Printf("分割 CIDR %s 失败: %v\n", cidrStr, err)
				continue
			}
			for _, subnet := range subnets {
				// 逐个处理子网中的 IP
				expandCIDR(subnet.String(), func(ip string) {
					for _, port := range ports { // **核心：遍历所有端口**
						// 速率限制检查
						if limiter != nil {
							ctx := context.Background()
							if err := limiter.Wait(ctx); err != nil {
								fmt.Printf("速率限制器错误: %v\n", err)
								return
							}
						}

						wg.Add(1)
						thread <- struct{}{} // 占用一个并发槽位
						go func(ip string, port int) {
							defer func() {
								<-thread // 释放一个并发槽位
								wg.Done()

								// 任务完成后更新进度
								newCompleted := atomic.AddInt64(&completed, 1)
								// 如果所有任务完成，关闭 done 通道
								if newCompleted >= total {
									once.Do(func() {
										close(done)
									})
								}
							}()

							// 扫描和检测 Cloudflare 服务
							if ok, dataCenter, tcpDuration := isOpenAndCloudflare(ip, port); ok {
								// 修复1：添加IP去重检查
								key := fmt.Sprintf("%s:%d", ip, port)

								seenMu.Lock()
								if seen[key] {
									seenMu.Unlock()
									return  // 已存在，跳过
								}
								seen[key] = true
								seenMu.Unlock()

								mu.Lock()
								validIPs = append(validIPs, fmt.Sprintf("%s %d", ip, port))
								mu.Unlock()

								dataCenterStr := dataCenter
								if dataCenterStr == "" {
									dataCenterStr = "未知"
								}

								// **修复：正确的打印顺序以防止进度条闪烁**
								printMu.Lock()
								// 1. 清除当前进度条行
								// **内联 clearLine 逻辑**
								fmt.Print("\r\033[2K") 
								// **内联 clearLine 逻辑结束**

								// 2. 打印发现消息 (自动换行，成为日志滚动部分)
								// 🚨 修正：统一使用 &printMu 作为打印锁
								printValidIP(ip, port, dataCenter, tcpDuration, locationMap, &printMu)

								// 3. 重新绘制进度条到新的底部行
								// **内联 printProgress 逻辑**
								completedVal := atomic.LoadInt64(&completed)
								percentage := 0.0
								if total > 0 {
									percentage = float64(completedVal) / float64(total) * 100.0
								}
								elapsed := time.Since(startTime)
								var etaStr string
								if completedVal == 0 || elapsed.Seconds() < 1 {
									etaStr = "计算中..."
								} else if completedVal >= total {
									etaStr = "0秒"
								} else {
									rate := float64(completedVal) / elapsed.Seconds()
									remaining := float64(total - completedVal)
									etaSeconds := remaining / rate
									etaDuration := time.Duration(etaSeconds * float64(time.Second))

									etaHours := int(etaDuration.Hours())
									etaMinutes := int(etaDuration.Minutes()) % 60
									etaSecondsInt := int(etaDuration.Seconds()) % 60

									// 修正后的 ETA 格式化逻辑
									if etaHours > 0 {
										etaStr = fmt.Sprintf("%02d小时 %02d分 %02d秒", etaHours, etaMinutes, etaSecondsInt)
									} else if etaMinutes > 0 {
										etaStr = fmt.Sprintf("%02d分 %02d秒", etaMinutes, etaSecondsInt)
									} else {
										etaStr = fmt.Sprintf("%d秒", etaSecondsInt)
									}
								}
								safePrintProgress(fmt.Sprintf(
                                    "扫描CIDR获取有效IP: %d/%d (%.2f%%) 预计剩余耗时: %s",
                                    completedVal, total, percentage, etaStr,
                                ))

								// **内联 printProgress 逻辑结束**

								printMu.Unlock()
							}
						}(ip, port)
					}
				})
			}
		}
	}
	
	wg.Wait() // 等待所有 goroutine 完成

	// 确保定时器停止
	once.Do(func() {
		close(done) 
	})
	
	// 等待定时器协程打印最终状态
	time.Sleep(250 * time.Millisecond) 

	// 扫描完成后,按顺序打印所有最终信息
	endTime := time.Now().In(cstZone) 
	duration := endTime.Sub(startTime)

	// 格式化耗时
	hours := int(duration.Hours())
	minutes := int(duration.Minutes()) % 60
	seconds := int(duration.Seconds()) % 60

	// 计算实际扫描速率
	scanRate := float64(completed) / duration.Seconds()

	// 生成扫描检测报告文本
	reportBuf := bytes.NewBufferString("")
	fmt.Fprintf(reportBuf, "*🎉 扫描CIDR检测报告*\n")
	fmt.Fprintf(reportBuf, "⏰ 扫描开始: `%s`\n", startTime.Format("2006/01/02 15:04:05"))
	fmt.Fprintf(reportBuf, "🏁 扫描结束: `%s`\n", endTime.Format("2006/01/02 15:04:05"))
	fmt.Fprintf(reportBuf, "⏱ 耗时: `%02d:%02d:%02d`\n", hours, minutes, seconds)
	fmt.Fprintf(reportBuf, "✅ 已完成: `%d` 总数: `%d` (完成率: `%.2f%%`)\n", total, total, 100.00)

	if len(validIPs) > 0 {
		// 写入有效IP到ip.txt
		err = writeToIPFile(validIPs)
		if err != nil {
			fmt.Printf("写入ip.txt失败: %v\n", err)
			if *telegramToken != "" && *telegramChatID != "" {
				sendTelegramMessage("*⚠️ 错误*\n写入ip.txt失败: " + escapeMarkdownV2(err.Error()))
			}
			return
		}
		fmt.Fprintf(reportBuf, "✅ 有效IP: `%d`个 已写入 `ip.txt`\n", len(validIPs))
	} else {
		fmt.Fprintln(reportBuf, "❌ 没有找到有效IP")
	}
	fmt.Fprintf(reportBuf, "📈 实际扫描速率: `%.2f` pps\n", scanRate)
	fmt.Fprintf(reportBuf, "🏁 IP端口扫描,检测完成")

	scanReport := reportBuf.String()
	fmt.Print(scanReport)

	// 发送扫描报告和文件到Telegram
	if len(validIPs) > 0 {
		sendTelegramMessage(scanReport)
		sendTelegramFile("ip.txt")
	} else if *telegramToken != "" && *telegramChatID != "" {
		sendTelegramMessage(scanReport)
	}
}

// estimateTotalTargets 估算总目标数（用于内存保护决策）
func estimateTotalTargets(cidrs []string, ports []int) int {
	total := 0
	for _, cidrStr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		ones, bits := ipNet.Mask.Size()
		var numIPs int
		if ipNet.IP.To4() != nil {
			// IPv4: 2^(32 - ones)
			numIPs = 1 << (32 - ones)
		} else {
			// IPv6: 限制估算，避免溢出（实际只扫描到/64）
			if ones < 64 {
				numIPs = 1 << (64 - ones) // 估算到/64
			} else {
				numIPs = 1 << (bits - ones)
			}
		}
		total += numIPs * len(ports)
		if total > maxPreCollectTargets {
			return total // 提前返回，避免过度计算
		}
	}
	return total
}

// 从文件中读取IP地址和端口,支持多种格式,包括IPv6
// 修改：保留域名，不解析为IP
func readIPs(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("无法打开文件 %s: %v", file, err)
	}
	defer f.Close()

	var ips []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var host, portStr string
		// 处理空格分隔: ip port
		if strings.Contains(line, " ") {
			parts := strings.Fields(line)
			if len(parts) > 2 {
				fmt.Printf("无效格式: %s\n", line)
				continue
			}
			host = parts[0]
			if len(parts) == 2 {
				portStr = parts[1]
			} else {
				portStr = "443"
			}
		} else {
			// 处理冒号分隔: host:port,对于IPv6可能是[ipv6]:port 或 ipv6:port
			if strings.Count(line, ":") > 1 {
				// 可能IPv6
				if strings.HasPrefix(line, "[") {
					// [ipv6]:port
					endBracket := strings.LastIndex(line, "]")
					if endBracket == -1 {
						fmt.Printf("无效IPv6格式: %s\n", line)
						continue
					}
					host = line[1:endBracket]
					if endBracket+1 < len(line) && line[endBracket+1] == ':' {
						portStr = line[endBracket+2:]
					} else {
						portStr = "443"
					}
				} else {
					// ipv6:port,无括号,最后:是端口分隔
					lastColon := strings.LastIndex(line, ":")
					if lastColon == -1 {
						host = line
						portStr = "443"
					} else {
						host = line[:lastColon]
						portStr = line[lastColon+1:]
					}
				}
			} else {
				// ipv4:port 或 domain:port
				parts := strings.SplitN(line, ":", 2)
				host = parts[0]
				if len(parts) == 2 {
					portStr = parts[1]
				} else {
					portStr = "443"
				}
			}
		}

		// 验证端口
		port, err := strconv.Atoi(portStr)
		if err != nil {
			fmt.Printf("无效端口: %s 在行: %s\n", portStr, line)
			continue
		}

		// 修改：保留原始输入（包括域名），不解析
		ips = append(ips, fmt.Sprintf("%s %d", host, port))
	}
	return ips, scanner.Err()
}

// downloadCIDRFromASN 从指定 URL 下载 ASN 的 CIDR 列表
func downloadCIDRFromASN(asn string) {
	urlStr := fmt.Sprintf("https://as.090227.xyz/AS%s", asn)

	// 优先获取带代理的客户端,如果获取失败则使用自定义配置的本地客户端
	client := getTelegramClient()
	if client == nil {
		// 修复安卓 DNS 问题: 强制使用 Go 纯 Go 解析器并指定公共 DNS
		dialer := &net.Dialer{
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 5 * time.Second}
					return d.DialContext(ctx, "udp", "8.8.8.8:53") // 强制使用 Google DNS
				},
			},
			Timeout: 10 * time.Second,
		}
		client = &http.Client{
			Transport: &http.Transport{DialContext: dialer.DialContext},
			Timeout:   15 * time.Second,
		}
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		errMsg := fmt.Sprintf("下载 CIDR 失败: %v", err)
		fmt.Println(errMsg)
		if *telegramToken != "" && *telegramChatID != "" {
			// 将错误信息放入代码块,避免点号等特殊字符导致解析失败
			sendTelegramMessage("*⚠️ 错误*\n下载失败: `" + escapeMarkdownV2(err.Error()) + "`")
			sendTelegramMessage("*🎉 程序运行结束*")
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取 CIDR 响应失败: %v\n", err)
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage("*⚠️ 错误*\n读取响应失败: `" + escapeMarkdownV2(err.Error()) + "`")
		}
		return
	}

	err = os.WriteFile(*cidrFile, body, 0644)
	if err != nil {
		fmt.Printf("保存 CIDR 文件 %s 失败: %v\n", *cidrFile, err)
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage("*⚠️ 错误*\n保存文件失败: `" + escapeMarkdownV2(err.Error()) + "`")
		}
		return
	}

	fmt.Printf("CIDR 列表已下载到 %s\n", *cidrFile)
	if *telegramToken != "" && *telegramChatID != "" {
		// 使用反引号包裹文件名,解决文件名中可能存在的点号问题
		sendTelegramMessage("*✅ 成功*\nCIDR 列表已下载到 `" + escapeMarkdownV2(*cidrFile) + "`")
	}
}

// 下载Cloudflare位置数据并保存到文件
func downloadLocations() {
	url := "https://raw.githubusercontent.com/Netrvin/cloudflare-colo-list/master/DC-Colos.json"
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("下载位置数据失败: %v\n", err)
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage("*⚠️ 错误*\n下载位置数据失败: " + escapeMarkdownV2(err.Error()))
		}
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取位置数据响应失败: %v\n", err)
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage("*⚠️ 错误*\n读取位置数据响应失败: " + escapeMarkdownV2(err.Error()))
		}
		return
	}
	err = os.WriteFile("locations.json", body, 0644)
	if err != nil {
		fmt.Printf("保存位置数据文件失败: %v\n", err)
		if *telegramToken != "" && *telegramChatID != "" {
			sendTelegramMessage("*⚠️ 错误*\n保存位置数据文件失败: " + escapeMarkdownV2(err.Error()))
		}
		return
	}
	if *telegramToken != "" && *telegramChatID != "" {
		sendTelegramMessage("*✅ 成功*\n位置数据已更新到 `locations.json`")
	}
}

// 分割大 CIDR 为更小子网(IPv4 /24, IPv6 /64)
func splitCIDR(cidrStr string) ([]*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("无效 CIDR: %s, 错误: %v", cidrStr, err)
	}
	var subnets []*net.IPNet
	ones, _ := ipNet.Mask.Size()
	subnetSize := 24
	if ipNet.IP.To4() == nil {
		subnetSize = 64 // 对于IPv6,使用 /64
	}
	if ones <= subnetSize {
		subnets = append(subnets, ipNet)
		return subnets, nil
	}
	first, _ := cidr.AddressRange(ipNet)
	count := 0
	for ip := first; ipNet.Contains(ip); ip = cidr.Inc(ip) {
		subnet, err := cidr.Subnet(ipNet, subnetSize, count)
		if err != nil {
			break // 停止如果错误
		}
		subnets = append(subnets, subnet)
		count++
	}
	return subnets, nil
}

// 展开CIDR为单个IP地址
func expandCIDR(cidrStr string, fn func(string)) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		fmt.Printf("无效 CIDR: %s, 错误: %v\n", cidrStr, err)
		return
	}
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		fn(ip.String())
	}
}

// 递增IP地址
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 从文件中读取CIDR列表
func readCIDRs(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("无法打开文件 %s: %v", file, err)
	}
	defer f.Close()

	var cidrs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err != nil {
			fmt.Printf("无效 CIDR: %s\n", line)
			continue
		}
		cidrs = append(cidrs, line)
	}
	return cidrs, scanner.Err()
}

// 解析端口参数,支持单个端口和端口范围
func parsePorts(portsStr string) []int {
	var ports []int
	portParts := strings.Split(portsStr, ",")
	for _, part := range portParts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			// 端口范围
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				fmt.Printf("无效端口范围: %s\n", part)
				continue
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				fmt.Printf("无效起始端口: %s\n", rangeParts[0])
				continue
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				fmt.Printf("无效结束端口: %s\n", rangeParts[1])
				continue
			}
			if start > end {
				fmt.Printf("无效端口范围: %s (起始端口大于结束端口)\n", part)
				continue
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err != nil {
				fmt.Printf("无效端口: %s\n", part)
				continue
			}
			ports = append(ports, port)
		}
	}
	return ports
}

// 将有效IP写入ip.txt
func writeToIPFile(ips []string) error {
	f, err := os.Create(*File)
	if err != nil {
		return fmt.Errorf("无法创建文件 %s: %v", *File, err)
	}
	defer f.Close()
	writer := bufio.NewWriter(f)
	for _, ip := range ips {
		fmt.Fprintln(writer, ip)
	}
	return writer.Flush()
}
