import requests
import re
import csv
import subprocess
import os
import logging
import sys
from io import StringIO
from typing import List, Tuple
from collections import defaultdict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from charset_normalizer import detect

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# 配置
URL = "https://raw.githubusercontent.com/gxiaobai2024/api/refs/heads/main/proxyip%20.csv"
IP_LIST_FILE = "ip.txt"
IPS_FILE = "ips.txt"
SPEEDTEST_SCRIPT = "./iptest.sh"
FINAL_CSV = "ip.csv"
INPUT_FILE = "input.csv"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com/"
}

# 指定需要写入 ips.txt 的国家代码
DESIRED_COUNTRIES = ['TW', 'JP', 'HK', 'SG', 'KR', 'IN', 'KP', 'VN', 'TH', 'MM']

# 国家代码到 emoji 和中文名称的映射
COUNTRY_LABELS = {
    'JP': ('🇯🇵', '日本'), 'KR': ('🇰🇷', '韩国'), 'SG': ('🇸🇬', '新加坡'),
    'TW': ('🇹🇼', '台湾'), 'HK': ('🇭🇰', '香港'), 'MY': ('🇲🇾', '马来西亚'),
    'TH': ('🇹🇭', '泰国'), 'ID': ('🇮🇩', '印度尼西亚'), 'PH': ('🇵🇭', '菲律宾'),
    'VN': ('🇻🇳', '越南'), 'IN': ('🇮🇳', '印度'), 'MO': ('🇲🇴', '澳门'),
    'KH': ('🇰🇭', '柬埔寨'), 'LA': ('🇱🇦', '老挝'), 'MM': ('🇲🇲', '缅甸'),
    'MN': ('🇲🇳', '蒙古'), 'KP': ('🇰🇵', '朝鲜'), 'US': ('🇺🇸', '美国'),
    'GB': ('🇬🇧', '英国'), 'DE': ('🇩🇪', '德国'), 'FR': ('🇫🇷', '法国'),
    'IT': ('🇮🇹', '意大利'), 'ES': ('🇪🇸', '西班牙'), 'NL': ('🇳🇱', '荷兰'),
    'FI': ('🇫🇮', '芬兰'), 'AU': ('🇦🇺', '澳大利亚'), 'CA': ('🇨🇦', '加拿大'),
    'NZ': ('🇳🇿', '新西兰'), 'BR': ('🇧🇷', '巴西'), 'RU': ('🇷🇺', '俄罗斯'),
    'PL': ('🇵🇱', '波兰'), 'UA': ('🇺🇦', '乌克兰'), 'CZ': ('🇨🇿', '捷克'),
    'HU': ('🇭🇺', '匈牙利'), 'RO': ('🇷🇴', '罗马尼亚'), 'SA': ('🇸🇦', '沙特阿拉伯'),
    'AE': ('🇦🇪', '阿联酋'), 'QA': ('🇶🇦', '卡塔尔'), 'IL': ('🇮🇱', '以色列'),
    'TR': ('🇹🇷', '土耳其'), 'IR': ('🇮🇷', '伊朗'),
    'CN': ('🇨🇳', '中国'), 'BD': ('🇧🇩', '孟加拉国'), 'PK': ('🇵🇰', '巴基斯坦'),
    'LK': ('🇱🇰', '斯里兰卡'), 'NP': ('🇳🇵', '尼泊尔'), 'BT': ('🇧🇹', '不丹'),
    'MV': ('🇲🇻', '马尔代夫'), 'BN': ('🇧🇳', '文莱'), 'TL': ('🇹🇱', '东帝汶'),
    'EG': ('🇪🇬', '埃及'), 'ZA': ('🇿🇦', '南非'), 'NG': ('🇳🇬', '尼日利亚'),
    'KE': ('🇰🇪', '肯尼亚'), 'GH': ('🇬🇭', '加纳'), 'MA': ('🇲🇦', '摩洛哥'),
    'DZ': ('🇩🇿', '阿尔及利亚'), 'TN': ('🇹🇳', '突尼斯'), 'AR': ('🇦🇷', '阿根廷'),
    'CL': ('🇨🇱', '智利'), 'CO': ('🇨🇴', '哥伦比亚'), 'PE': ('🇵🇪', '秘鲁'),
    'MX': ('🇲🇽', '墨西哥'), 'VE': ('🇻🇪', '委内瑞拉'), 'SE': ('🇸🇪', '瑞典'),
    'NO': ('🇳🇴', '挪威'), 'DK': ('🇩🇰', '丹麦'), 'CH': ('🇨🇭', '瑞士'),
    'AT': ('🇦🇹', '奥地利'), 'BE': ('🇧🇪', '比利时'), 'IE': ('🇮🇪', '爱尔兰'),
    'PT': ('🇵🇹', '葡萄牙'), 'GR': ('🇬🇷', '希腊'), 'BG': ('🇬🇷', '保加利亚'),
    'SK': ('🇸🇰', '斯洛伐克'), 'SI': ('🇸🇮', '斯洛文尼亚'), 'HR': ('🇭🇷', '克罗地亚'),
    'RS': ('🇷🇸', '塞尔维亚'), 'BA': ('🇧🇦', '波黑'), 'MK': ('🇲🇰', '北马其顿'),
    'AL': ('🇦🇱', '阿尔巴尼亚'), 'KZ': ('🇰🇿', '哈萨克斯坦'), 'UZ': ('🇺🇿', '乌兹别克斯坦'),
    'KG': ('🇰🇬', '吉尔吉斯斯坦'), 'TJ': ('🇹🇯', '塔吉克斯坦'), 'TM': ('🇹🇲', '土库曼斯坦'),
    'GE': ('🇬🇪', '格鲁吉亚'), 'AM': ('🇦🇲', '亚美尼亚'), 'AZ': ('🇦🇿', '阿塞拜疆'),
    'KW': ('🇰🇼', '科威特'), 'BH': ('🇧🇭', '巴林'), 'OM': ('🇴🇲', '阿曼'),
    'JO': ('🇯🇴', '约旦'), 'LB': ('🇱🇧', '黎巴嫩'), 'SY': ('🇸🇾', '叙利亚'),
    'IQ': ('🇮🇶', '伊拉克'), 'YE': ('🇾🇪', '也门'),
    'EE': ('🇪🇪', '爱沙尼亚'), 'LV': ('🇱🇻', '拉脱维亚'), 'LT': ('🇱🇹', '立陶宛')
}

def is_ip(s: str) -> bool:
    """验证 IP 地址格式"""
    return bool(re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", s))

def is_port(s: str) -> bool:
    """验证端口号"""
    try:
        port = int(s)
        return 1 <= port <= 65535
    except ValueError:
        return False

def extract_ip_ports_from_file(file_path: str) -> List[Tuple[str, str, str]]:
    """从本地文件提取 IPv4 地址、端口和国家代码，只保留指定国家"""
    if not os.path.exists(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []

    # 读取文件内容为二进制，检测编码
    with open(file_path, "rb") as f:
        raw_data = f.read()
    result = detect(raw_data)
    encoding = result.get("encoding", "utf-8")
    logger.info(f"检测到文件 {file_path} 的编码: {encoding}")

    # 以检测到的编码解码
    try:
        content = raw_data.decode(encoding)
    except UnicodeDecodeError as e:
        logger.error(f"无法以 {encoding} 解码文件 {file_path}: {e}")
        return []

    logger.info(f"从本地文件 {file_path} 读取内容 (长度: {len(content)} 字节)")

    # 统一换行符
    content = content.replace('\r\n', '\n').replace('\r', '\n')

    # 尝试不同的分隔符解析 CSV
    f = StringIO(content)
    delimiters = [',', '\t', ';']
    for delimiter in delimiters:
        f.seek(0)
        reader = csv.reader(f, delimiter=delimiter)
        rows = list(reader)
        if len(rows) > 1 and len(rows[0]) > 1:
            break
    else:
        logger.error("无法确定 CSV 分隔符")
        return []

    header = rows[0]
    data_rows = rows[1:]
    logger.info(f"CSV 字段数: {len(header)}, 示例行: {data_rows[0] if data_rows else '无数据'}")

    # 假设字段位置（根据 input.csv 结构调整）
    ip_col = 0      # IP 地址
    port_col = 1    # 端口
    country_col = 2 # 国家代码 (TW, JP 等)

    logger.info(f"字段位置 - IP: {ip_col}, Port: {port_col}, Country: {country_col}")

    ip_ports = []
    for row in data_rows:
        if len(row) <= max(ip_col, port_col, country_col or -1):
            continue
        try:
            ip = row[ip_col].strip()
            if not is_ip(ip):
                logger.debug(f"无效 IP: {ip}")
                continue

            port = row[port_col].strip()
            if not is_port(port):
                port = "443"  # 默认使用 443 端口
            port = str(int(port))

            country = row[country_col].strip().upper()
            if country not in DESIRED_COUNTRIES:
                continue

            ip_ports.append((ip, port, country))

        except (ValueError, IndexError) as e:
            logger.debug(f"跳过无效行: {row} - {e}")
            continue

    logger.info(f"提取到 {len(ip_ports)} 个符合条件的节点")
    return ip_ports

def fetch_and_extract_ip_ports_from_url(url: str) -> List[Tuple[str, str, str]]:
    """从 URL 获取并提取 IPv4 地址、端口和国家代码，只保留指定国家"""
    try:
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, timeout=30, headers=HEADERS, stream=True)
        response.raise_for_status()
        raw_content = b""
        for chunk in response.iter_content(chunk_size=8192):
            raw_content += chunk
        logger.info(f"从 URL 获取内容: {url} (长度: {len(raw_content)} 字节)")
    except Exception as e:
        logger.error(f"获取内容失败: {e}")
        return []

    # 检测编码
    result = detect(raw_content)
    encoding = result.get("encoding", "utf-8")
    logger.info(f"检测到 URL 内容的编码: {encoding}")

    # 以检测到的编码解码
    try:
        content = raw_content.decode(encoding)
    except UnicodeDecodeError as e:
        logger.error(f"无法以 {encoding} 解码 URL 内容: {e}")
        return []

    # 统一换行符
    content = content.replace('\r\n', '\n').replace('\r', '\n')

    # 尝试不同的分隔符解析 CSV
    f = StringIO(content)
    delimiters = [',', '\t', ';']
    for delimiter in delimiters:
        f.seek(0)
        reader = csv.reader(f, delimiter=delimiter)
        rows = list(reader)
        if len(rows) > 1 and len(rows[0]) > 1:
            break
    else:
        logger.error("无法确定 CSV 分隔符")
        return []

    header = rows[0]
    data_rows = rows[1:]
    logger.info(f"CSV 字段数: {len(header)}, 示例行: {data_rows[0] if data_rows else '无数据'}")

    # 假设字段位置（根据 URL 返回的 CSV 结构调整）
    ip_col = 0      # IP 地址
    port_col = 1    # 端口
    country_col = 2 # 国家代码 (TW, JP 等)

    logger.info(f"字段位置 - IP: {ip_col}, Port: {port_col}, Country: {country_col}")

    ip_ports = []
    for row in data_rows:
        if len(row) <= max(ip_col, port_col, country_col or -1):
            continue
        try:
            ip = row[ip_col].strip()
            if not is_ip(ip):
                logger.debug(f"无效 IP: {ip}")
                continue

            port = row[port_col].strip()
            if not is_port(port):
                port = "443"  # 默认使用 443 端口
            port = str(int(port))

            country = row[country_col].strip().upper()
            if country not in DESIRED_COUNTRIES:
                continue

            ip_ports.append((ip, port, country))

        except (ValueError, IndexError) as e:
            logger.debug(f"跳过无效行: {row} - {e}")
            continue

    logger.info(f"提取到 {len(ip_ports)} 个符合条件的节点")
    return ip_ports

def write_ip_list(ip_ports: List[Tuple[str, str, str]]) -> str:
    """写入 ip.txt，格式为 'ip port'"""
    if not ip_ports:
        logger.error(f"无有效节点，无法生成 {IP_LIST_FILE}")
        return None
    try:
        with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
            for ip, port, _ in ip_ports:
                f.write(f"{ip} {port}\n")
        logger.info(f"生成 {IP_LIST_FILE}，包含 {len(ip_ports)} 个节点")
        if os.path.exists(IP_LIST_FILE):
            logger.info(f"确认 {IP_LIST_FILE} 已生成，文件大小: {os.path.getsize(IP_LIST_FILE)} 字节")
        else:
            logger.error(f"错误：{IP_LIST_FILE} 未生成")
        return IP_LIST_FILE
    except Exception as e:
        logger.error(f"写入 {IP_LIST_FILE} 失败: {e}")
        return None

def run_speed_test() -> str:
    """运行测速脚本"""
    try:
        # 检查 ip.txt 是否存在
        if not os.path.exists(IP_LIST_FILE):
            logger.error(f"{IP_LIST_FILE} 不存在，无法运行测速")
            return None

        with open(IP_LIST_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            ip_count = len(lines)
            if ip_count == 0:
                logger.error(f"{IP_LIST_FILE} 为空，无法运行测速")
                return None
            logger.info(f"{IP_LIST_FILE} 包含 {ip_count} 个 IP")
            logger.info(f"{IP_LIST_FILE} 前 5 行内容: {lines[:5]}")

        cmd = [SPEEDTEST_SCRIPT]
        logger.info(f"运行测速命令: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            encoding='utf-8',
            errors='replace'
        )

        logger.info(f"iptest.sh stdout: {result.stdout}")
        if result.stderr:
            logger.info(f"iptest.sh stderr: {result.stderr}")

        if result.returncode != 0:
            logger.error(f"iptest.sh 运行失败，返回码: {result.returncode}")
            return None

        if os.path.exists(FINAL_CSV):
            logger.info(f"测速完成，结果保存到 {FINAL_CSV}")
            with open(FINAL_CSV, "r", encoding="utf-8") as f:
                logger.info(f"ip.csv 前 5 行内容:\n{''.join(f.readlines()[:5])}")
            return FINAL_CSV
        else:
            logger.error(f"测速完成，但未生成 {FINAL_CSV}")
            return None
    except Exception as e:
        logger.error(f"运行测速失败: {e}")
        return None

def filter_speed_and_deduplicate(csv_file: str):
    """去重 ip.csv 中的节点"""
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在，跳过去重")
        return
    seen = set()
    final_rows = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            logger.error(f"{csv_file} 为空，跳过去重")
            return
        for row in reader:
            if len(row) < 3:  # 确保行有足够列（IP、端口、速度）
                continue
            key = (row[0], row[1])
            if key not in seen:
                seen.add(key)
                final_rows.append(row)

    if not final_rows:
        logger.info(f"没有符合条件的节点，删除 {csv_file}")
        os.remove(csv_file)
        return

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(final_rows)
    logger.info(f"去重完成，{csv_file} 包含 {len(final_rows)} 条记录")

def generate_ips_file(csv_file: str, ip_ports: List[Tuple[str, str, str]]):
    """从 ip.csv 读取 IP 和端口，添加国家标签并写入 ips.txt"""
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在，跳过生成 {IPS_FILE}")
        return

    # 创建 IP:Port 到国家的映射
    ip_port_to_country = {(ip, port): country for ip, port, country in ip_ports}

    # 读取 ip.csv，获取测速后的 IP 和端口
    final_nodes = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
            logger.info(f"ip.csv 表头: {header}")
        except StopIteration:
            logger.error(f"ip.csv 为空，跳过生成 {IPS_FILE}")
            return
        for row in reader:
            if len(row) < 3:  # 确保行有足够列（IP、端口、速度）
                continue
            ip, port = row[0], row[1]
            key = (ip, port)
            if key in ip_port_to_country:
                country = ip_port_to_country[key]
                final_nodes.append((ip, port, country))
            else:
                logger.debug(f"未找到 {ip}:{port} 的国家标签，跳过")

    if not final_nodes:
        logger.info(f"没有符合条件的节点，跳过生成 {IPS_FILE}")
        return

    # 统计每个国家的出现次数，为重复国家添加序号
    country_count = defaultdict(int)
    labeled_nodes = []
    for ip, port, country in final_nodes:
        country_count[country] += 1
        emoji, name = COUNTRY_LABELS.get(country, ('🌐', country))
        label = f"{emoji}{name}-{country_count[country]}"
        labeled_nodes.append((ip, port, label))

    # 写入 ips.txt
    with open(IPS_FILE, "w", encoding="utf-8") as f:
        for ip, port, label in labeled_nodes:
            f.write(f"{ip}:{port}#{label}\n")
    logger.info(f"生成 {IPS_FILE}，包含 {len(labeled_nodes)} 个节点")

def main(prefer_url: bool = False):
    """主函数"""
    ip_ports = []
    if not prefer_url and os.path.exists(INPUT_FILE):
        # 从本地 input.csv 获取 IP 和端口
        ip_ports = extract_ip_ports_from_file(INPUT_FILE)
        if not ip_ports:
            logger.error("未找到符合条件的节点")
            sys.exit(1)
    else:
        # 从 URL 获取 IP 和端口
        ip_ports = fetch_and_extract_ip_ports_from_url(URL)
        if not ip_ports:
            logger.error("未找到符合条件的节点")
            sys.exit(1)

    # 写入 ip.txt
    ip_file = write_ip_list(ip_ports)
    if not ip_file:
        logger.error("无法生成 ip.txt，终止程序")
        sys.exit(1)

    with open(ip_file, "r", encoding="utf-8") as f:
        logger.info(f"ip.txt 内容:\n{f.read()}")

    # 运行测速
    csv_file = run_speed_test()
    if csv_file:
        filter_speed_and_deduplicate(csv_file)
        if os.path.exists(csv_file):
            generate_ips_file(csv_file, ip_ports)
        else:
            logger.info("无符合条件的节点，跳过生成 ips.txt")
    else:
        logger.info("无测速结果")

if __name__ == "__main__":
    prefer_url = '--url-first' in sys.argv
    logger.info(f"数据源优先级: {'URL 优先' if prefer_url else '本地文件优先'}")
    logger.info(f"筛选国家: {DESIRED_COUNTRIES}")
    main(prefer_url=prefer_url)