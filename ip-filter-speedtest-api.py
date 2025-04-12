import requests
import re
import csv
import subprocess
import os
import logging
import sys
import threading
import importlib.util
import time
import json
from typing import List, Tuple, Dict
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
URL = "https://raw.githubusercontent.com/gxiaobani2024/api/refs/heads/main/proxyip%20.csv"
IP_LIST_FILE = "ip.txt"
IPS_FILE = "ips.txt"
SPEEDTEST_SCRIPT = "./iptest.sh"
FINAL_CSV = "ip.csv"
INPUT_FILE = "input.csv"
COUNTRY_CACHE_FILE = "country_cache.json"
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
    'LK': ('🇱🇰', '斯里兰卡'), 'NP': ('🇵🇵', '尼泊尔'), 'BT': ('🇧🇹', '不丹'),
    'MV': ('🇲🇻', '马尔代夫'), 'BN': ('🇧🇳', '文莱'), 'TL': ('🇹🇱', '东帝汶'),
    'EG': ('🇪🇬', '埃及'), 'ZA': ('🇿🇦', '南非'), 'NG': ('🇳🇬', '尼日利亚'),
    'KE': ('🇰🇪', '肯尼亚'), 'GH': ('🇬🇭', '加纳'), 'MA': ('🇲🇦', '摩洛哥'),
    'DZ': ('🇩🇿', '阿尔及利亚'), 'TN': ('🇹🇳', '突尼斯'), 'AR': ('🇦🇷', '阿根廷'),
    'CL': ('🇨🇱', '智利'), 'CO': ('🇨🇴', '哥伦比亚'), 'PE': ('🇵🇪', '秘鲁'),
    'MX': ('🇲🇽', '墨西哥'), 'VE': ('🇻🇪', '委内瑞拉'), 'SE': ('🇸🇪', '瑞典'),
    'NO': ('🇳🇴', '挪威'), 'DK': ('🇩🇰', '丹麦'), 'CH': ('🇨🇭', '瑞士'),
    'AT': ('🇦🇹', '奥地利'), 'BE': ('🇧🇪', '比利时'), 'IE': ('🇮🇪', '爱尔兰'),
    'PT': ('🇵🇹', '葡萄牙'), 'GR': ('🇬🇷', '希腊'), 'BG': ('🇧🇬', '保加利亚'),
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

# 非标准国家名称映射
COUNTRY_ALIASES = {
    'SOUTH KOREA': 'KR', 'KOREA': 'KR', 'HONG KONG': 'HK', 'HONGKONG': 'HK',
    'UNITED STATES': 'US', 'USA': 'US', 'UNITED KINGDOM': 'GB', 'UK': 'GB', '英国': 'GB',
    'JAPAN': 'JP', 'JPN': 'JP', 'TAIWAN': 'TW', 'TWN': 'TW', 'SINGAPORE': 'SG',
    'FRANCE': 'FR', 'GERMANY': 'DE', 'NETHERLANDS': 'NL', 'AUSTRALIA': 'AU',
    'CANADA': 'CA', 'BRAZIL': 'BR', 'RUSSIA': 'RU', 'INDIA': 'IN', 'CHINA': 'CN',
    'KOREA, REPUBLIC OF': 'KR', 'REPUBLIC OF KOREA': 'KR', 'VIET NAM': 'VN',
    'THAILAND': 'TH', 'BURMA': 'MM', 'MYANMAR': 'MM', 'NORTH KOREA': 'KP'
}

# 加载国家缓存（仅用于调试）
def load_country_cache() -> Dict[str, str]:
    if os.path.exists(COUNTRY_CACHE_FILE):
        try:
            with open(COUNTRY_CACHE_FILE, 'r', encoding='utf-8') as f:
                cache = json.load(f)
                logger.info(f"加载缓存: {len(cache)} 条记录")
                return cache
        except Exception as e:
            logger.warning(f"加载国家缓存失败: {e}")
    return {}

# 保存国家缓存（仅用于调试）
def save_country_cache(cache: Dict[str, str]):
    try:
        with open(COUNTRY_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
        logger.info(f"保存缓存: {len(cache)} 条记录")
    except Exception as e:
        logger.warning(f"保存国家缓存失败: {e}")

# 检查依赖
REQUIRED_PACKAGES = ['requests', 'charset_normalizer']

def check_dependencies():
    for pkg in REQUIRED_PACKAGES:
        if not importlib.util.find_spec(pkg):
            logger.error(f"缺少依赖包: {pkg}，请安装")
            sys.exit(1)

def detect_delimiter(lines: List[str]) -> str:
    """检测 CSV 分隔符"""
    comma_count = sum(1 for line in lines[:5] if ',' in line and line.strip())
    semicolon_count = sum(1 for line in lines[:5] if ';' in line and line.strip())
    tab_count = sum(1 for line in lines[:5] if '\t' in line and line.strip())
    space_count = sum(1 for line in lines[:5] if ' ' in line and line.strip())

    if comma_count > max(semicolon_count, tab_count, space_count) and comma_count > 0:
        return ','
    elif semicolon_count > max(comma_count, tab_count, space_count) and semicolon_count > 0:
        return ';'
    elif tab_count > max(comma_count, semicolon_count, space_count) and tab_count > 0:
        return '\t'
    elif space_count > max(comma_count, semicolon_count, tab_count) and space_count > 0:
        return ' '
    return None

def is_valid_ip(ip: str) -> bool:
    """验证 IP 地址（IPv4 或 IPv6）"""
    ipv4_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    ipv6_pattern = re.compile(r'^(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$')
    return bool(ipv4_pattern.match(ip) or ipv6_pattern.match(ip.strip('[]')))

def is_valid_port(port: str) -> bool:
    """验证端口号"""
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def is_country_like(value: str) -> bool:
    """判断字段是否像国家代码或名称"""
    if not value:
        return False
    value_upper = value.upper().strip()
    if re.match(r'^[A-Z]{2}$', value_upper) and value_upper in COUNTRY_LABELS:
        return True
    if value_upper in COUNTRY_ALIASES:
        return True
    return False

def standardize_country(country: str) -> str:
    """标准化国家代码，宽松匹配"""
    if not country:
        return ''
    country_clean = country.strip().upper()
    logger.debug(f"标准化国家: 输入={country}, 转换为={country_clean}")
    if country_clean in COUNTRY_LABELS:
        return country_clean
    if country_clean in COUNTRY_ALIASES:
        return COUNTRY_ALIASES[country_clean]
    logger.warning(f"未识别的国家: {country}")
    return ''

def find_country_column(lines: List[str], delimiter: str) -> Tuple[int, int, int]:
    """无表头时，遍历行列确定国家列"""
    country_col = -1
    ip_col = 0
    port_col = 1
    sample_lines = [line for line in lines[:5] if line.strip() and not line.startswith('#')]
    if not sample_lines:
        return ip_col, port_col, country_col

    col_matches = defaultdict(int)
    total_rows = len(sample_lines)
    max_cols = max(len(line.split(delimiter)) for line in sample_lines)

    for line in sample_lines:
        fields = line.split(delimiter)
        for col, field in enumerate(fields):
            field = field.strip()
            if is_country_like(field):
                col_matches[col] += 1

    if col_matches:
        country_col = max(col_matches, key=col_matches.get)
        match_rate = col_matches[country_col] / total_rows
        if match_rate < 0.5:
            country_col = -1
        else:
            logger.info(f"通过遍历确定国家列: 第 {country_col + 1} 列 (匹配率: {match_rate:.2%})")

    return ip_col, port_col, country_col

def fetch_and_extract_ip_ports_from_url(url: str) -> List[Tuple[str, int, str]]:
    """从 URL 获取并提取 IP、端口和国家（若存在），去重"""
    server_port_pairs = []
    invalid_lines = []

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
        logger.error(f"获取 URL 内容失败: {e}")
        return []

    result = detect(raw_content)
    encoding = result.get("encoding", "utf-8")
    logger.info(f"检测到 URL 内容的编码: {encoding}")

    try:
        content = raw_content.decode(encoding)
    except UnicodeDecodeError:
        logger.warning(f"无法以 {encoding} 解码，尝试 UTF-8")
        try:
            content = raw_content.decode('utf-8', errors='replace')
        except UnicodeDecodeError as e:
            logger.error(f"解码 URL 内容失败: {e}")
            return []

    logger.debug(f"URL 内容前5行: {content.splitlines()[:5]}")
    if not content.strip():
        logger.error("URL 内容为空")
        return []

    content = content.replace('\r\n', '\n').replace('\r', '\n')
    lines = content.splitlines()

    delimiter = detect_delimiter(lines)
    logger.info(f"检测到的分隔符: {delimiter if delimiter else '未检测到，使用正则匹配'}")
    if not delimiter:
        return []

    ip_col, port_col, country_col = 0, 1, -1
    lines_to_process = lines
    if lines and lines[0].strip() and not lines[0].startswith('#'):
        header = lines[0].strip().split(delimiter)
        for idx, col in enumerate(header):
            col_lower = col.strip().lower()
            if col_lower in ['ip', 'address', 'ip地址']:
                ip_col = idx
            elif col_lower in ['port', '端口', '端口口']:
                port_col = idx
            elif col_lower in ['country', '国家', 'code', 'nation', 'location']:
                country_col = idx
        if country_col != -1:
            logger.info(f"通过表头确定国家列: 第 {country_col + 1} 列 ({header[country_col]})")
            lines_to_process = lines[1:]
        else:
            logger.info("表头中未找到国家列，尝试遍历行列")
            ip_col, port_col, country_col = find_country_column(lines, delimiter)

    ip_port_pattern = re.compile(r'(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]|(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))[ :,\t](\d{1,5})')

    for i, line in enumerate(lines_to_process):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        match = ip_port_pattern.match(line)
        if match:
            server = match.group(1).strip('[]')
            port = int(match.group(4))
            country = ''
            if country_col != -1:
                fields = line.split(delimiter)
                if country_col < len(fields):
                    country = standardize_country(fields[country_col].strip())
            if is_valid_port(str(port)):
                server_port_pairs.append((server, port, country))
                logger.debug(f"解析到: {server}:{port}, 国家: {country or '无'}")
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid port range)")
            continue

        fields = line.split(delimiter)
        if len(fields) < max(ip_col, port_col) + 1:
            invalid_lines.append(f"Line {i}: {line} (Too few fields)")
            continue

        server = fields[ip_col].strip('[]')
        port_str = fields[port_col].strip()
        country = ''
        if country_col != -1 and country_col < len(fields):
            country = standardize_country(fields[country_col].strip())
        else:
            for col, field in enumerate(fields):
                field = field.strip()
                if is_country_like(field):
                    country = standardize_country(field)
                    if country:
                        logger.debug(f"逐行找到国家: {field} -> {country} (第 {col + 1} 列)")
                        break

        if is_valid_ip(server) and is_valid_port(port_str):
            server_port_pairs.append((server, int(port_str), country))
            logger.debug(f"解析到: {server}:{port_str}, 国家: {country or '无'}")
        else:
            invalid_lines.append(f"Line {i}: {line} (Invalid IP or port)")

    # 去重（但 input.csv 已无重复，此步骤可跳过）
    unique_server_port_pairs = list(dict.fromkeys(server_port_pairs))
    logger.info(f"从 URL 解析到 {len(server_port_pairs)} 个原始记录")
    logger.info(f"去重后共 {len(unique_server_port_pairs)} 个 server:port:country 对")
    if not unique_server_port_pairs:
        logger.error("未解析到有效 IP，可能原因：URL 数据无效或格式错误")
    if invalid_lines:
        logger.info(f"发现 {len(invalid_lines)} 个无效条目: {invalid_lines[:5]}")

    return unique_server_port_pairs

def extract_ip_ports_from_file(file_path: str) -> List[Tuple[str, int, str]]:
    """从本地文件提取 IP、端口和国家（若存在）"""
    server_port_pairs = []
    invalid_lines = []

    if not os.path.exists(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []

    with open(file_path, "rb") as f:
        raw_data = f.read()
    if not raw_data:
        logger.error(f"文件 {file_path} 为空")
        return []

    result = detect(raw_data)
    encoding = result.get("encoding", "utf-8")
    logger.info(f"检测到文件 {file_path} 的编码: {encoding}")

    try:
        content = raw_data.decode(encoding)
    except UnicodeDecodeError:
        logger.warning(f"无法以 {encoding} 解码，尝试 UTF-8")
        try:
            content = raw_data.decode('utf-8', errors='replace')
        except UnicodeDecodeError as e:
            logger.error(f"解码文件 {file_path} 失败: {e}")
            return []

    logger.info(f"从本地文件 {file_path} 读取内容 (长度: {len(content)} 字节)")
    logger.debug(f"文件 {file_path} 内容前5行: {content.splitlines()[:5]}")

    content = content.replace('\r\n', '\n').replace('\r', '\n')
    lines = content.splitlines()

    delimiter = detect_delimiter(lines)
    logger.info(f"检测到的分隔符: {delimiter if delimiter else '未检测到，使用正则匹配'}")
    if not delimiter:
        return []

    ip_col, port_col, country_col = 0, 1, -1
    lines_to_process = lines
    if lines and lines[0].strip() and not lines[0].startswith('#'):
        header = lines[0].strip().split(delimiter)
        for idx, col in enumerate(header):
            col_lower = col.strip().lower()
            if col_lower in ['ip', 'address', 'ip地址']:
                ip_col = idx
            elif col_lower in ['port', '端口', '端口口']:
                port_col = idx
            elif col_lower in ['country', '国家', 'code', 'nation', 'location', '国际代码']:
                country_col = idx
        if country_col != -1:
            logger.info(f"通过表头确定国家列: 第 {country_col + 1} 列 ({header[country_col]})")
            lines_to_process = lines[1:]
        else:
            logger.info("表头中未找到国家列，尝试遍历行列")
            ip_col, port_col, country_col = find_country_column(lines, delimiter)

    ip_port_pattern = re.compile(r'(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]|(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))[ :,\t](\d{1,5})')

    for i, line in enumerate(lines_to_process):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        match = ip_port_pattern.match(line)
        if match:
            server = match.group(1).strip('[]')
            port = int(match.group(4))
            country = ''
            if country_col != -1:
                fields = line.split(delimiter)
                if country_col < len(fields):
                    country = standardize_country(fields[country_col].strip())
            if is_valid_port(str(port)):
                server_port_pairs.append((server, port, country))
                logger.debug(f"解析到: {server}:{port}, 国家: {country or '无'}")
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid port range)")
            continue

        fields = line.split(delimiter)
        if len(fields) < max(ip_col, port_col) + 1:
            invalid_lines.append(f"Line {i}: {line} (Too few fields)")
            continue

        server = fields[ip_col].strip('[]')
        port_str = fields[port_col].strip()
        country = ''
        if country_col != -1 and country_col < len(fields):
            country = standardize_country(fields[country_col].strip())
        else:
            for col, field in enumerate(fields):
                field = field.strip()
                if is_country_like(field):
                    country = standardize_country(field)
                    if country:
                        logger.debug(f"逐行找到国家: {field} -> {country} (第 {col + 1} 列)")
                        break

        if is_valid_ip(server) and is_valid_port(port_str):
            server_port_pairs.append((server, int(port_str), country))
            logger.debug(f"解析到: {server}:{port_str}, 国家: {country or '无'}")
        else:
            invalid_lines.append(f"Line {i}: {line} (Invalid IP or port)")

    # input.csv 已无重复，跳过去重
    logger.info(f"从文件解析到 {len(server_port_pairs)} 个记录")
    if not server_port_pairs:
        logger.error("未解析到有效 IP，可能原因：文件数据无效或格式错误")
    if invalid_lines:
        logger.info(f"发现 {len(invalid_lines)} 个无效条目: {invalid_lines[:5]}")

    return server_port_pairs

def write_ip_list(ip_ports: List[Tuple[str, int, str]]) -> str:
    """写入 ip.txt，格式为 'ip port'，使用 input.csv 的国家信息筛选"""
    if not ip_ports:
        logger.error(f"无有效节点，无法生成 {IP_LIST_FILE}")
        return None
    filtered_ip_ports = []
    filtered_out = []
    logger.info(f"开始筛选 {len(ip_ports)} 个节点的国家")
    for ip, port, country in ip_ports:
        if country and country in DESIRED_COUNTRIES:
            filtered_ip_ports.append((ip, port))
            logger.debug(f"保留: {ip}:{port}, 国家={country}")
        else:
            filtered_out.append((ip, port, country))
            logger.debug(f"过滤: {ip}:{port}, 国家={country}")
    if filtered_out:
        logger.info(f"过滤掉 {len(filtered_out)} 个不符合 {DESIRED_COUNTRIES} 的节点: {filtered_out[:5]}")
    logger.info(f"筛选后得到 {len(filtered_ip_ports)} 个节点")
    if not filtered_ip_ports:
        logger.error(f"无任何有效节点，无法生成 {IP_LIST_FILE}")
        return None
    try:
        os.makedirs(os.path.dirname(IP_LIST_FILE) or '.', exist_ok=True)
        with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
            for ip, port in filtered_ip_ports:
                f.write(f"{ip} {port}\n")
        logger.info(f"生成 {IP_LIST_FILE}，包含 {len(filtered_ip_ports)} 个节点")
        # 打印 ip.txt 前几行
        with open(IP_LIST_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[:5]
            logger.info(f"{IP_LIST_FILE} 前5行: {lines}")
    except PermissionError as e:
        logger.error(f"无权限写入 {IP_LIST_FILE}: {e}")
        return None
    except Exception as e:
        logger.error(f"写入 {IP_LIST_FILE} 失败: {e}")
        return None
    return IP_LIST_FILE

def run_speed_test() -> str:
    """运行测速脚本"""
    if not os.path.exists(SPEEDTEST_SCRIPT):
        logger.error(f"测速脚本 {SPEEDTEST_SCRIPT} 不存在")
        return None
    if not os.access(SPEEDTEST_SCRIPT, os.X_OK):
        logger.info(f"测速脚本 {SPEEDTEST_SCRIPT} 无执行权限，尝试修复")
        try:
            os.chmod(SPEEDTEST_SCRIPT, 0o755)
            logger.info(f"已设置 {SPEEDTEST_SCRIPT} 可执行权限")
        except Exception as e:
            logger.error(f"设置执行权限失败: {e}")
            return None
    if not os.path.exists(IP_LIST_FILE):
        logger.error(f"IP 列表文件 {IP_LIST_FILE} 不存在")
        return None
    with open(IP_LIST_FILE, 'r', encoding='utf-8') as f:
        ip_lines = f.readlines()
        logger.info(f"{IP_LIST_FILE} 包含 {len(ip_lines)} 行数据")
        if not ip_lines:
            logger.error(f"{IP_LIST_FILE} 为空")
            return None
    try:
        cmd = [
            SPEEDTEST_SCRIPT,
            f"-file={IP_LIST_FILE}",
            "-tls=true",
            "-speedtest=5",
            "-speedlimit=10",
            "-url=speed.cloudflare.com/__down?bytes=50000000",
            "-max=200",
            f"-outfile={FINAL_CSV}"
        ]
        logger.info(f"运行测速命令: {' '.join(cmd)}")
        process = subprocess.Popen(
            ' '.join(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,
            encoding='utf-8',
            errors='replace'
        )
        stdout_lines = []
        stderr_lines = []
        def read_stream(stream, lines):
            while True:
                line = stream.readline()
                if not line:
                    break
                print(line.strip())
                lines.append(line)
        stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, stdout_lines))
        stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, stderr_lines))
        stdout_thread.start()
        stderr_thread.start()
        stdout_thread.join()
        stderr_thread.join()
        return_code = process.wait()
        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)
        logger.info(f"iptest.sh stdout: {stdout}")
        logger.info(f"iptest.sh stderr: {stderr}")
        if return_code == 0 and os.path.exists(FINAL_CSV):
            logger.info(f"测速完成，结果保存到 {FINAL_CSV}")
            return FINAL_CSV
        else:
            logger.error(f"测速失败或未生成 {FINAL_CSV}: {stderr}")
            return None
    except Exception as e:
        logger.error(f"运行测速失败: {e}")
        return None

def filter_speed_and_deduplicate(csv_file: str):
    """去重 ip.csv 并按下载速度降序排序，处理非数值速度值"""
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在，跳过去重")
        return
    seen = set()
    final_rows = []
    invalid_speed_rows = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if len(row) < 4:
                continue
            key = (row[0], row[1])
            if key not in seen:
                seen.add(key)
                speed = row[3].strip()
                try:
                    float(speed)
                except ValueError:
                    invalid_speed_rows.append((row[0], row[1], speed, row))
                    row[3] = '0.0'  # 将无效速度设为 0.0
                final_rows.append(row)
    if not final_rows:
        logger.info(f"没有符合条件的节点，删除 {csv_file}")
        os.remove(csv_file)
        return
    if invalid_speed_rows:
        logger.warning(f"发现 {len(invalid_speed_rows)} 个无效下载速度值: {invalid_speed_rows[:5]}")
        invalid_speed_dist = defaultdict(int)
        for _, _, speed, _ in invalid_speed_rows:
            invalid_speed_dist[speed] += 1
        logger.info(f"无效速度值分布: {dict(invalid_speed_dist)}")
    try:
        final_rows.sort(key=lambda x: float(x[3]) if x[3] else 0.0, reverse=True)
    except (ValueError, IndexError) as e:
        logger.error(f"按下载速度排序失败: {e}，保持原顺序")
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(final_rows)
    logger.info(f"去重并排序完成，{csv_file} 包含 {len(final_rows)} 条记录")
    # 打印 ip.csv 前几行
    with open(csv_file, "r", encoding="utf-8") as f:
        lines = f.readlines()[:5]
        logger.info(f"{csv_file} 前5行: {lines}")

def generate_ips_file(csv_file: str):
    """读取 ip.csv，使用 csv 中的国家信息，写入 ips.txt，仅保留指定国家"""
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在，跳过生成 {IPS_FILE}")
        return
    final_nodes = []
    filtered_out = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        country_col = header.index("国际代码") if "国际代码" in header else -1
        if country_col == -1:
            logger.error(f"{csv_file} 中未找到 '国际代码' 列，无法生成 {IPS_FILE}")
            return
        for row in reader:
            if len(row) < 2:
                continue
            ip, port = row[0], row[1]
            if not is_valid_ip(ip) or not is_valid_port(port):
                logger.debug(f"无效 IP 或端口: {ip}:{port}")
                continue
            country = row[country_col] if country_col < len(row) else ''
            country = standardize_country(country)
            if country in DESIRED_COUNTRIES:
                final_nodes.append((ip, int(port), country))
            else:
                filtered_out.append((ip, port, country))
                logger.debug(f"过滤掉 {ip}:{port}，国家 {country} 不在 {DESIRED_COUNTRIES}")
    if filtered_out:
        logger.info(f"过滤掉 {len(filtered_out)} 个不符合 {DESIRED_COUNTRIES} 的节点: {filtered_out[:5]}")
    if not final_nodes:
        logger.info(f"没有符合条件的节点，跳过生成 {IPS_FILE}")
        return
    country_count = defaultdict(int)
    labeled_nodes = []
    for ip, port, country in final_nodes:
        country_count[country] += 1
        emoji, name = COUNTRY_LABELS.get(country, ('🌐', '未知'))
        label = f"{emoji}{name}-{country_count[country]}"
        labeled_nodes.append((ip, port, label))
    with open(IPS_FILE, "w", encoding="utf-8") as f:
        for ip, port, label in labeled_nodes:
            f.write(f"{ip}:{port}#{label}\n")
    logger.info(f"生成 {IPS_FILE}，包含 {len(labeled_nodes)} 个节点")
    # 打印 ips.txt 前几行
    with open(IPS_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()[:5]
        logger.info(f"{IPS_FILE} 前5行: {lines}")

def main():
    """主函数"""
    try:
        check_dependencies()
        logger.info("开始执行主流程")
        ip_ports = []
        if os.path.exists(INPUT_FILE):
            logger.info(f"从 {INPUT_FILE} 获取 IP")
            ip_ports = extract_ip_ports_from_file(INPUT_FILE)
        else:
            logger.info(f"本地文件 {INPUT_FILE} 不存在，尝试从 URL 获取 IP: {URL}")
            ip_ports = fetch_and_extract_ip_ports_from_url(URL)
        logger.info(f"获取到 {len(ip_ports)} 个 IP 记录")
        if not ip_ports:
            logger.error("未获取到有效的 IP 和端口")
            sys.exit(1)
        ip_list_file = write_ip_list(ip_ports)
        if not ip_list_file:
            logger.error("生成 ip.txt 失败")
            sys.exit(1)
        csv_file = run_speed_test()
        if not csv_file:
            logger.error("测速失败")
            sys.exit(1)
        filter_speed_and_deduplicate(csv_file)
        generate_ips_file(csv_file)
    except Exception as e:
        logger.error(f"主流程异常: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()