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
import argparse
import random
from typing import List, Tuple, Dict
from collections import defaultdict
from charset_normalizer import detect
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import geoip2.database
from pathlib import Path
import tempfile
import atexit
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("speedtest.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# 配置
IP_LIST_FILE = "ip.txt"
IPS_FILE = "ips.txt"
FINAL_CSV = "ip.csv"
INPUT_FILE = "input.csv"
TEMP_FILE = os.path.join(tempfile.gettempdir(), "temp_proxy.csv")
TEMP_FILE_CACHE_DURATION = 3600
INPUT_URL = os.getenv("INPUT_URL", "https://raw.githubusercontent.com/gxiaobai2024/api/refs/heads/main/proxyip%20.csv")
COUNTRY_CACHE_FILE = "country_cache.json"
GEOIP_DB_PATH = Path(os.path.abspath("GeoLite2-Country.mmdb"))
GEOIP_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/releases/download/2025.04.10/GeoLite2-Country.mmdb"
GEOIP_DB_URL_BACKUP = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={}&suffix=tar.gz"
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY", "")
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com/"
}
DESIRED_COUNTRIES = ['TW', 'JP', 'HK', 'SG', 'KR', 'IN', 'KP', 'VN', 'TH', 'MM']
REQUIRED_PACKAGES = ['requests', 'charset_normalizer', 'geoip2']
COUNTRY_LABELS = {
    'JP': ('🇯🇵', '日本'), 'KR': ('🇰🇷', '韩国'), 'SG': ('🇸🇬', '新加坡'),
    'TW': ('🇹🇼', '台湾'), 'HK': ('🇭🇰', '香港'), 'MY': ('🇲🇾', '马来西亚'),
    'TH': ('🇹🇭', '泰国'), 'ID': ('🇮🇩', '印度尼西亚'), 'PH': ('🇵🇭', '菲律宾'),
    'VN': ('🇻🇳', '越南'), 'IN': ('🇮🇳', '印度'), 'MO': ('🇲🇴', '澳门'),
    'KH': ('🇰🇭', '柬埔寨'), 'LA': ('🇱🇦', '老挝'), 'MM': ('🇲🇲', '缅甸'),
    'MN': ('🇲🇳', '蒙古'), 'KP': ('🇰🇵', '朝鲜'), 'US': ('🇺🇸', '美国'),
    'GB': ('🇬🇧', '英国'), 'DE': ('🇩🇪', '德国'), 'FR': ('🇫🇷', '法国'),
    'IT': ('🇮🇹', '意大利'), 'ES': ('🇸🇪', '西班牙'), 'NL': ('🇳🇱', '荷兰'),
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
    'PT': ('🇵🇹', '葡萄牙'), 'GR': ('🇬🇷', '希腊'), 'BG': ('🇬🇬', '保加利亚'),
    'SK': ('🇸🇰', '斯洛伐克'), 'SI': ('🇸🇮', '斯洛文尼亚'), 'HR': ('🇭🇷', '克罗地亚'),
    'RS': ('🇷🇸', '塞尔维亚'), 'BA': ('🇧🇦', '波黑'), 'MK': ('🇲🇰', '北马其顿'),
    'AL': ('🇦🇱', '阿尔巴尼亚'), 'KZ': ('🇻🇿', '哈萨克斯坦'), 'UZ': ('🇺🇿', '乌兹别克斯坦'),
    'KG': ('🇰🇬', '吉尔吉斯斯坦'), 'TJ': ('🇹🇯', '塔吉克斯坦'), 'TM': ('🇹🇲', '土库曼斯坦'),
    'GE': ('🇬🇪', '格鲁吉亚'), 'AM': ('🇦🇲', '亚美尼亚'), 'AZ': ('🇦🇿', '阿塞拜疆'),
    'KW': ('🇰🇼', '科威特'), 'BH': ('🇧🇭', '巴林'), 'OM': ('🇴🇲', '阿曼'),
    'JO': ('🇯🇴', '约旦'), 'LB': ('🇱🇧', '黎巴嫩'), 'SY': ('🇸🇾', '叙利亚'),
    'IQ': ('🇮🇶', '伊拉克'), 'YE': ('🇾🇪', '也门'),
    'EE': ('🇪🇪', '爱沙尼亚'), 'LV': ('�LV', '拉脱维亚'), 'LT': ('🇱🇹', '立陶宛')
}
COUNTRY_ALIASES = {
    'SOUTH KOREA': 'KR', 'KOREA': 'KR', 'REPUBLIC OF KOREA': 'KR', 'KOREA, REPUBLIC OF': 'KR',
    'HONG KONG': 'HK', 'HONGKONG': 'HK', 'HK SAR': 'HK',
    'UNITED STATES': 'US', 'USA': 'US', 'U.S.': 'US', 'UNITED STATES OF AMERICA': 'US',
    'UNITED KINGDOM': 'GB', 'UK': 'GB', 'GREAT BRITAIN': 'GB', '英国': 'GB',
    'JAPAN': 'JP', 'JPN': 'JP', '日本': 'JP',
    'TAIWAN': 'TW', 'TWN': 'TW', 'TAIWAN, PROVINCE OF CHINA': 'TW', '台湾': 'TW',
    'SINGAPORE': 'SG', 'SGP': 'SG', '新加坡': 'SG',
    'FRANCE': 'FR', 'FRA': 'FR', '法国': 'FR',
    'GERMANY': 'DE', 'DEU': 'DE', '德国': 'DE',
    'NETHERLANDS': 'NL', 'NLD': 'NL', '荷兰': 'NL',
    'AUSTRALIA': 'AU', 'AUS': 'AU', '澳大利亚': 'AU',
    'CANADA': 'CA', 'CAN': 'CA', '加拿大': 'CA',
    'BRAZIL': 'BR', 'BRA': 'BR', '巴西': 'BR',
    'RUSSIA': 'RU', 'RUS': 'RU', '俄罗斯': 'RU',
    'INDIA': 'IN', 'IND': 'IN', '印度': 'IN',
    'CHINA': 'CN', 'CHN': 'CN', '中国': 'CN',
    'VIET NAM': 'VN', 'VIETNAM': 'VN', '越南': 'VN',
    'THAILAND': 'TH', 'THA': 'TH', '泰国': 'TH',
    'BURMA': 'MM', 'MYANMAR': 'MM', '缅甸': 'MM',
    'NORTH KOREA': 'KP', 'KOREA, DEMOCRATIC PEOPLE\'S REPUBLIC OF': 'KP', '朝鲜': 'KP'
}

# 查找测速脚本
def find_speedtest_script() -> str:
    candidates = ["./iptest.sh", "./iptest"]
    for candidate in candidates:
        if os.path.exists(candidate):
            if not os.access(candidate, os.X_OK):
                try:
                    os.chmod(candidate, 0o755)
                    logger.info(f"已为 {candidate} 添加执行权限")
                except Exception as e:
                    logger.error(f"无法为 {candidate} 添加执行权限: {e}")
                    continue
            if candidate == "./iptest.sh":
                if not os.path.exists("./iptest"):
                    logger.error("找到 iptest.sh，但未找到 iptest")
                    continue
                if not os.access("./iptest", os.X_OK):
                    try:
                        os.chmod("./iptest", 0o755)
                        logger.info("已为 ./iptest 添加执行权限")
                    except Exception as e:
                        logger.error(f"无法为 ./iptest 添加执行权限: {e}")
                        continue
            logger.info(f"找到测速脚本: {candidate}")
            return candidate
    logger.error("未找到测速脚本")
    return None

SPEEDTEST_SCRIPT = find_speedtest_script()

# GeoIP 全局变量
geoip_reader = None

def cleanup_temp_file():
    if os.path.exists(TEMP_FILE):
        try:
            os.remove(TEMP_FILE)
            logger.info(f"清理临时文件: {TEMP_FILE}")
        except Exception as e:
            logger.warning(f"清理临时文件失败: {e}")

atexit.register(cleanup_temp_file)

def download_geoip_database(url: str, dest_path: Path) -> bool:
    logger.info(f"下载 GeoIP 数据库: {url}")
    try:
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504, 429])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, timeout=60, stream=True, allow_redirects=True, headers=HEADERS)
        response.raise_for_status()
        logger.debug(f"HTTP 状态码: {response.status_code}, 内容类型: {response.headers.get('Content-Type', '')}")
        with open(dest_path, "wb") as f:
            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    total_size += len(chunk)
        logger.info(f"GeoIP 数据库下载完成: {dest_path} (大小: {total_size} 字节)")
        if not dest_path.exists() or total_size < 100:
            logger.error(f"下载的 GeoIP 数据库无效或为空: {dest_path}")
            dest_path.unlink(missing_ok=True)
            return False
        try:
            with geoip2.database.Reader(dest_path) as reader:
                logger.debug("GeoIP 数据库文件格式验证通过")
        except Exception as e:
            logger.error(f"GeoIP 数据库文件损坏: {e}")
            dest_path.unlink(missing_ok=True)
            return False
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"下载 GeoIP 数据库失败: {e}")
        return False
    except IOError as e:
        logger.error(f"写入 GeoIP 数据库文件失败: {e}")
        return False

def download_geoip_database_maxmind(dest_path: Path) -> bool:
    if not MAXMIND_LICENSE_KEY:
        logger.warning("未设置 MAXMIND_LICENSE_KEY，跳过 MaxMind 下载")
        return False
    url = GEOIP_DB_URL_BACKUP.format(MAXMIND_LICENSE_KEY)
    logger.info(f"尝试从 MaxMind 下载 GeoIP 数据库: {url}")
    try:
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504, 429])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, timeout=60, stream=True, headers=HEADERS)
        response.raise_for_status()
        temp_tar = dest_path.with_suffix(".tar.gz")
        with open(temp_tar, "wb") as f:
            total_size = 0
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                total_size += len(chunk)
        logger.info(f"MaxMind 数据库下载完成: {temp_tar} (大小: {total_size} 字节)")
        import tarfile
        with tarfile.open(temp_tar, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("GeoLite2-Country.mmdb"):
                    tar.extract(member, dest_path.parent)
                    extracted_path = dest_path.parent / member.name
                    extracted_path.rename(dest_path)
                    break
        temp_tar.unlink(missing_ok=True)
        if not dest_path.exists() or dest_path.stat().st_size < 100:
            logger.error(f"解压后的 GeoIP 数据库无效: {dest_path}")
            dest_path.unlink(missing_ok=True)
            return False
        try:
            with geoip2.database.Reader(dest_path) as reader:
                logger.debug("MaxMind GeoIP 数据库验证通过")
        except Exception as e:
            logger.error(f"MaxMind GeoIP 数据库损坏: {e}")
            dest_path.unlink(missing_ok=True)
            return False
        return True
    except Exception as e:
        logger.error(f"从 MaxMind 下载 GeoIP 数据库失败: {e}")
        temp_tar.unlink(missing_ok=True)
        return False

def init_geoip_reader():
    global geoip_reader
    logger.info(f"当前工作目录: {os.getcwd()}")
    logger.info(f"GeoIP 数据库路径: {GEOIP_DB_PATH}")
    if not GEOIP_DB_PATH.exists():
        logger.warning(f"GeoIP 数据库 {GEOIP_DB_PATH} 不存在，尝试下载")
        if not download_geoip_database(GEOIP_DB_URL, GEOIP_DB_PATH):
            logger.warning("主下载源失败，尝试 MaxMind 备用源")
            if not download_geoip_database_maxmind(GEOIP_DB_PATH):
                logger.error("无法下载 GeoIP 数据库，退出")
                sys.exit(1)
    try:
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        logger.debug("GeoIP 数据库加载成功")
    except Exception as e:
        logger.error(f"GeoIP 数据库加载失败: {e}")
        GEOIP_DB_PATH.unlink(missing_ok=True)
        if not download_geoip_database(GEOIP_DB_URL, GEOIP_DB_PATH):
            logger.warning("主下载源失败，尝试 MaxMind 备用源")
            if not download_geoip_database_maxmind(GEOIP_DB_PATH):
                logger.error("重新下载 GeoIP 数据库失败，退出")
                sys.exit(1)
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

def close_geoip_reader():
    global geoip_reader
    if geoip_reader:
        geoip_reader.close()
        geoip_reader = None
        logger.debug("GeoIP 数据库连接已关闭")

atexit.register(close_geoip_reader)

def check_dependencies():
    for pkg in REQUIRED_PACKAGES:
        if not importlib.util.find_spec(pkg):
            logger.error(f"缺少依赖包: {pkg}，请安装")
            sys.exit(1)
    init_geoip_reader()

def load_country_cache() -> Dict[str, str]:
    if os.path.exists(COUNTRY_CACHE_FILE):
        try:
            with open(COUNTRY_CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"加载国家缓存失败: {e}")
    return {}

def save_country_cache(cache: Dict[str, str]):
    try:
        with open(COUNTRY_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f"保存国家缓存失败: {e}")

def is_temp_file_valid(temp_file: str) -> bool:
    if not os.path.exists(temp_file):
        return False
    mtime = os.path.getmtime(temp_file)
    current_time = time.time()
    if (current_time - mtime) > TEMP_FILE_CACHE_DURATION:
        logger.info(f"临时文件 {temp_file} 已过期 (修改时间: {mtime})")
        return False
    if os.path.getsize(temp_file) < 10:
        logger.warning(f"临时文件 {temp_file} 内容过小，可能无效")
        return False
    return True

def detect_delimiter(lines: List[str]) -> str:
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
    ipv4_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    ipv6_pattern = re.compile(r'^(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$')
    return bool(ipv4_pattern.match(ip) or ipv6_pattern.match(ip.strip('[]')))

def is_valid_port(port: str) -> bool:
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def is_country_like(value: str) -> bool:
    if not value:
        return False
    value_upper = value.upper().strip()
    if re.match(r'^[A-Z]{2}$', value_upper) and value_upper in COUNTRY_LABELS:
        return True
    if value_upper in COUNTRY_ALIASES:
        return True
    return False

def standardize_country(country: str) -> str:
    if not country:
        return ''
    country_clean = re.sub(r'[^a-zA-Z\s]', '', country).strip().upper()
    if country_clean in COUNTRY_LABELS:
        logger.debug(f"国家代码匹配: {country} -> {country_clean}")
        return country_clean
    if country_clean in COUNTRY_ALIASES:
        mapped = COUNTRY_ALIASES[country_clean]
        logger.debug(f"通过映射表转换国家: {country} -> {mapped}")
        return mapped
    country_clean = country_clean.replace(' ', '')
    for alias, code in COUNTRY_ALIASES.items():
        alias_clean = alias.replace(' ', '')
        if country_clean == alias_clean:
            logger.debug(f"通过模糊匹配转换国家: {country} -> {code}")
            return code
    logger.warning(f"未识别的国家代码: {country}")
    return ''

def find_country_column(lines: List[str], delimiter: str) -> Tuple[int, int, int]:
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

def fetch_and_save_to_temp_file(url: str) -> str:
    logger.info(f"下载 URL: {url} 到临时文件 {TEMP_FILE}")
    try:
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504, 429])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, timeout=60, headers=HEADERS, stream=True)
        response.raise_for_status()
        with open(TEMP_FILE, "wb") as f:
            raw_content = b""
            for chunk in response.iter_content(chunk_size=8192):
                raw_content += chunk
                f.write(chunk)
        logger.info(f"内容已下载到临时文件: {TEMP_FILE} (大小: {len(raw_content)} 字节)")
        return TEMP_FILE
    except Exception as e:
        logger.error(f"下载 URL {url} 失败: {e}")
        logger.info("请检查网络连接或 URL 是否有效")
        return ''

def extract_ip_ports_from_file(file_path: str) -> List[Tuple[str, int, str]]:
    if not os.path.exists(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []
    start_time = time.time()
    with open(file_path, "rb") as f:
        raw_data = f.read()
    result = detect(raw_data)
    encoding = result.get("encoding", "utf-8")
    logger.info(f"检测到文件 {file_path} 的编码: {encoding}")
    try:
        content = raw_data.decode(encoding)
    except UnicodeDecodeError as e:
        logger.error(f"无法以 {encoding} 解码文件 {file_path}: {e}")
        return []
    ip_ports = extract_ip_ports_from_content(content)
    logger.info(f"从文件 {file_path} 解析完成 (耗时: {time.time() - start_time:.2f} 秒)")
    return ip_ports

def extract_ip_ports_from_content(content: str) -> List[Tuple[str, int, str]]:
    server_port_pairs = []
    invalid_lines = []
    content = content.replace('\r\n', '\n').replace('\r', '\n')
    lines = content.splitlines()
    if not lines:
        logger.error("内容为空，无法解析")
        return []
    logger.info(f"输入内容样本（前5行）: {lines[:5]}")
    try:
        data = json.loads(content)
        for item in data:
            ip = item.get('ip', '')
            port = item.get('port', '')
            country = standardize_country(item.get('country', '') or item.get('countryCode', '') or item.get('location', ''))
            if is_valid_ip(ip) and is_valid_port(str(port)):
                server_port_pairs.append((ip, int(port), country))
                logger.debug(f"从 JSON 解析到: {ip}:{port}, 国家: {country or '无'}")
        logger.info(f"从 JSON 解析到 {len(server_port_pairs)} 个节点")
        return list(dict.fromkeys(server_port_pairs))
    except json.JSONDecodeError:
        logger.debug("内容不是 JSON，尝试 CSV 或正则解析")
    delimiter = detect_delimiter(lines)
    logger.info(f"检测到的分隔符: {delimiter if delimiter else '未检测到，使用正则匹配'}")
    ip_col, port_col, country_col = 0, 1, -1
    lines_to_process = lines
    if lines and lines[0].strip() and not lines[0].startswith('#'):
        header = lines[0].strip().split(delimiter or ',')
        for idx, col in enumerate(header):
            col_lower = col.strip().lower()
            if col_lower in ['ip', 'address', 'ip地址']:
                ip_col = idx
            elif col_lower in ['port', '端口', '端口口']:
                port_col = idx
            elif col_lower in ['country', '国家', 'code', 'nation', 'location', 'countrycode', 'region']:
                country_col = idx
        if country_col != -1:
            logger.info(f"通过表头确定国家列: 第 {country_col + 1} 列 ({header[country_col]})")
            lines_to_process = lines[1:]
        else:
            logger.info("表头中未找到国家列，尝试遍历行列")
            if delimiter:
                ip_col, port_col, country_col = find_country_column(lines, delimiter)
    ip_port_pattern = re.compile(
        r'(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]|(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))[ :,\t](\d{1,5})'
    )
    for i, line in enumerate(lines_to_process):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = ip_port_pattern.match(line)
        if match:
            server = match.group(1).strip('[]')
            port = int(match.group(4))
            country = ''
            if delimiter and country_col != -1:
                fields = line.split(delimiter)
                if country_col < len(fields):
                    country = standardize_country(fields[country_col].strip())
            if is_valid_port(str(port)):
                server_port_pairs.append((server, port, country))
                logger.debug(f"解析到: {server}:{port}, 国家: {country or '无'}")
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid port range)")
            continue
        if delimiter:
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
                    if is_country_like(field) or field.upper() in COUNTRY_ALIASES:
                        country = standardize_country(field)
                        if country:
                            logger.debug(f"逐行找到国家: {field} -> {country} (第 {col + 1} 列)")
                            break
            if is_valid_ip(server) and is_valid_port(port_str):
                server_port_pairs.append((server, int(port_str), country))
                logger.debug(f"解析到: {server}:{port_str}, 国家: {country or '无'}")
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid IP or port)")
        else:
            invalid_lines.append(f"Line {i}: {line} (No valid format detected)")
    if invalid_lines:
        logger.info(f"发现 {len(invalid_lines)} 个无效条目: {invalid_lines[:5]}")
    else:
        logger.info("无无效行")
    logger.info(f"解析到 {len(server_port_pairs)} 个 IP:端口对")
    unique_server_port_pairs = list(dict.fromkeys(server_port_pairs))
    logger.info(f"去重后共 {len(unique_server_port_pairs)} 个 server:port:country 对")
    return unique_server_port_pairs

def get_country_from_ip(ip: str, cache: Dict[str, str]) -> str:
    if ip in cache:
        return cache[ip]
    try:
        response = geoip_reader.country(ip)
        country_code = response.country.iso_code or ''
        if country_code:
            cache[ip] = country_code
            logger.debug(f"IP {ip} 国家代码: {country_code}")
            return country_code
        return ''
    except Exception as e:
        logger.error(f"查询 IP {ip} 国家失败: {e}")
        return ''

def test_initial_latency(ip_ports: List[Tuple[str, int, str]], max_workers: int = 50, timeout: int = 7, use_http: bool = False) -> List[Tuple[str, int, str, float]]:
    """并行测试节点延迟（ping 或 HTTP）"""
    logger.info(f"开始测试 {len(ip_ports)} 个节点的初始延迟 {'(HTTP)' if use_http else '(ping)'}")
    start_time = time.time()
    results = []
    result_queue = Queue()

    if use_http:
        def test_node(ip: str, port: int, country: str):
            try:
                # 尝试 HTTPS 和 HTTP，优先常用端口
                for scheme in ['https', 'http']:
                    for test_port in [port, 443, 80]:
                        start = time.time()
                        url = f"{scheme}://{ip}:{test_port}"
                        response = requests.head(url, timeout=timeout, headers=HEADERS, allow_redirects=True)
                        if response.status_code < 400:
                            latency = (time.time() - start) * 1000  # ms
                            result_queue.put((ip, port, country, latency))
                            logger.debug(f"节点 {ip}:{port} {scheme}://{ip}:{test_port} 延迟: {latency:.2f} ms")
                            return
                result_queue.put((ip, port, country, float('inf')))
                logger.debug(f"节点 {ip}:{port} 所有协议/端口测试失败")
            except Exception as e:
                result_queue.put((ip, port, country, float('inf')))
                logger.debug(f"节点 {ip}:{port} HTTP 测试失败: {str(e)}")
    else:
        def test_node(ip: str, port: int, country: str):
            try:
                cmd = ["ping", "-c", "3", "-W", "1", ip]
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout, text=True)
                match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms', output)
                if match:
                    latency = float(match.group(1))
                    result_queue.put((ip, port, country, latency))
                    logger.debug(f"节点 {ip}:{port} ping 延迟: {latency:.2f} ms")
                else:
                    result_queue.put((ip, port, country, float('inf')))
                    logger.debug(f"节点 {ip}:{port} ping 无有效 RTT")
            except Exception as e:
                result_queue.put((ip, port, country, float('inf')))
                logger.debug(f"节点 {ip}:{port} ping 失败: {str(e)}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(test_node, ip, port, country) for ip, port, country in ip_ports]
        for future in futures:
            try:
                future.result(timeout=timeout + 2)
            except Exception as e:
                logger.warning(f"节点测试超时或异常: {e}")

    while not result_queue.empty():
        results.append(result_queue.get())

    valid_count = len([r for r in results if r[3] != float('inf')])
    logger.info(f"延迟测试完成，耗时: {time.time() - start_time:.2f} 秒，测试节点: {len(ip_ports)}，有效节点: {valid_count}")
    return results

def write_ip_list(ip_ports: List[Tuple[str, int, str]], target_nodes: int = 500, latency_threshold: float = 500.0) -> str:
    if not ip_ports:
        logger.error(f"无有效节点，无法生成 {IP_LIST_FILE}")
        return None

    start_time = time.time()
    country_cache = load_country_cache()
    filtered_ip_ports = []
    country_counts = defaultdict(int)
    filtered_counts = defaultdict(int)
    initial_limit = 8000  # 增加采样上限
    logger.info(f"开始筛选 {len(ip_ports)} 个节点")

    # 采样
    if len(ip_ports) > initial_limit:
        logger.info(f"节点数超 {initial_limit}，随机采样")
        ip_ports = random.sample(ip_ports, initial_limit)
        logger.info(f"采样后: {len(ip_ports)} 个节点")
    else:
        logger.info(f"节点数 {len(ip_ports)} 未达上限，无需采样")

    # 测试延迟
    use_http = False
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "1", "8.8.8.8"], stderr=subprocess.STDOUT, timeout=2)
        logger.info("ping 测试通过，使用 ping 延迟")
    except Exception as e:
        logger.warning(f"ping 测试失败 ({str(e)})，切换到 HTTP 延迟")
        use_http = True

    latency_results = test_initial_latency(ip_ports, max_workers=50, timeout=7, use_http=use_http)
    valid_results = [(ip, port, country, latency) for ip, port, country, latency in latency_results if latency != float('inf')]
    logger.info(f"有效延迟节点: {len(valid_results)}")

    # 筛选 DESIRED_COUNTRIES
    desired_results = []
    for ip, port, country, latency in latency_results:  # 使用全结果，避免丢失无效节点
        country_from_geoip = country or get_country_from_ip(ip, country_cache)
        if country_from_geoip in DESIRED_COUNTRIES:
            desired_results.append((ip, port, country_from_geoip, latency))
            country_counts[country_from_geoip] += 1
            logger.debug(f"保留节点 {ip}:{port} ({country_from_geoip}, 延迟: {latency if latency != float('inf') else '无效'} ms)")
        else:
            filtered_counts[country_from_geoip or '未知'] += 1
            logger.debug(f"过滤节点 {ip}:{port} (GeoIP: {country_from_geoip or '未知'})")

    logger.info(f"筛选结果 - 保留国家: {dict(country_counts)}")
    logger.info(f"筛选结果 - 过滤国家: {dict(filtered_counts)}")

    if not desired_results:
        logger.warning(f"无符合 {DESIRED_COUNTRIES} 的节点，尝试写入所有有效节点")
        # 回退：写入所有有效节点
        desired_results = [(ip, port, country, latency) for ip, port, country, latency in valid_results]
        if not desired_results:
            logger.error(f"仍无有效节点，无法生成 {IP_LIST_FILE}")
            return None

    # 按延迟排序
    desired_results.sort(key=lambda x: x[3])
    filtered_results = []
    if latency_threshold > 0:
        filtered_results = [(ip, port, country, latency) for ip, port, country, latency in desired_results if latency <= latency_threshold and latency != float('inf')]
        logger.info(f"延迟 <= {latency_threshold} ms 的节点: {len(filtered_results)}")
        if len(filtered_results) < 50:  # 放宽最小节点阈值
            logger.warning(f"延迟阈值节点不足 ({len(filtered_results)} < 50)，退回 Top {target_nodes}")
            filtered_results = [r for r in desired_results if r[3] != float('inf')][:target_nodes]
    else:
        filtered_results = [r for r in desired_results if r[3] != float('inf')][:target_nodes]
        logger.info(f"筛选 Top {target_nodes} 节点")

    filtered_ip_ports = [(ip, port) for ip, port, _, _ in filtered_results]

    if not filtered_ip_ports:
        logger.warning(f"无符合延迟要求的节点，生成空 {IP_LIST_FILE}")
        with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
            pass
        return IP_LIST_FILE

    # 写入 ip.txt
    with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
        for ip, port in filtered_ip_ports:
            f.write(f"{ip} {port}\n")
    logger.info(f"生成 {IP_LIST_FILE}，包含 {len(filtered_ip_ports)} 个节点 (耗时: {time.time() - start_time:.2f} 秒)")

    # 验证国家分布
    verify_counts = defaultdict(int)
    for ip, port in filtered_ip_ports:
        country = get_country_from_ip(ip, country_cache)
        verify_counts[country or '未知'] += 1
    logger.info(f"ip.txt 国家分布验证: {dict(verify_counts)}")
    if filtered_ip_ports:
        logger.debug(f"ip.txt 前5个节点样本: {filtered_ip_ports[:5]}")

    save_country_cache(country_cache)
    return IP_LIST_FILE

def run_speed_test() -> str:
    if not SPEEDTEST_SCRIPT:
        logger.error("测速脚本未找到，跳过测速")
        return None
    if not os.path.exists(IP_LIST_FILE):
        logger.error(f"IP 列表文件 {IP_LIST_FILE} 不存在")
        return None
    if not os.access(SPEEDTEST_SCRIPT, os.X_OK):
        logger.error(f"测速脚本 {SPEEDTEST_SCRIPT} 不可执行")
        return None

    start_time = time.time()
    batch_size = 20
    max_time_seconds = 480
    temp_dir = tempfile.mkdtemp()
    output_files = []

    with open(IP_LIST_FILE, "r", encoding="utf-8") as f:
        ip_lines = f.readlines()
    logger.info(f"ip.txt 包含 {len(ip_lines)} 个节点")

    for i in range(0, len(ip_lines), batch_size):
        if time.time() - start_time > max_time_seconds:
            logger.warning(f"接近时间限制 ({max_time_seconds} 秒)，停止测速")
            break
        batch_lines = ip_lines[i:i + batch_size]
        batch_file = os.path.join(temp_dir, f"batch_{i}.txt")
        batch_output = os.path.join(temp_dir, f"batch_{i}.csv")
        with open(batch_file, "w", encoding="utf-8") as f:
            f.writelines(batch_lines)
        cmd = [
            SPEEDTEST_SCRIPT,
            f"-file={batch_file}",
            "-tls=true",
            "-speedtest=3",
            "-speedlimit=8",
            "-url=speed.cloudflare.com/__down?bytes=1000000",
            "-max=10",
            "-timeout=10",
            f"-outfile={batch_output}"
        ]
        logger.info(f"运行批次 {i//batch_size + 1} 命令: {' '.join(cmd)}")
        batch_start_time = time.time()
        try:
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
            return_code = process.wait(timeout=60)
            stdout = ''.join(stdout_lines)
            stderr = ''.join(stderr_lines)
            logger.info(f"批次 {i//batch_size + 1} stdout: {stdout}")
            if stderr:
                logger.warning(f"批次 {i//batch_size + 1} stderr: {stderr}")
            logger.info(f"批次 {i//batch_size + 1} 耗时: {time.time() - batch_start_time:.2f} 秒")
            if return_code == 0 and os.path.exists(batch_output):
                output_files.append(batch_output)
            else:
                logger.warning(f"批次 {i//batch_size + 1} 失败，退出码: {return_code}")
        except subprocess.TimeoutExpired:
            logger.error(f"批次 {i//batch_size + 1} 超时，强制终止")
            process.kill()
        except Exception as e:
            logger.error(f"批次 {i//batch_size + 1} 失败: {e}")

    if not output_files:
        logger.error("无有效测速结果")
        return None

    # 合并 CSV
    all_rows = []
    header = None
    for idx, output_file in enumerate(output_files):
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                file_header = next(reader, None)
                if not header:
                    header = file_header
                for row in reader:
                    if len(row) >= len(header):
                        all_rows.append(row)
        except Exception as e:
            logger.warning(f"读取批次文件 {output_file} 失败: {e}")

    if not all_rows:
        logger.error("合并后无有效节点")
        return None

    with open(FINAL_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(all_rows)

    logger.info(f"测速完成，生成 {FINAL_CSV}，包含 {len(all_rows)} 个节点 (耗时: {time.time() - start_time:.2f} 秒)")
    return FINAL_CSV

def filter_speed_and_deduplicate(csv_file: str):
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在，跳过去重")
        return
    seen = set()
    final_rows = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if len(row) < 4:
                continue
            key = (row[0], row[1])
            if key not in seen:
                seen.add(key)
                final_rows.append(row)
    if not final_rows:
        logger.info(f"没有符合条件的节点，删除 {csv_file}")
        os.remove(csv_file)
        return
    try:
        final_rows.sort(key=lambda x: float(x[9]) if x[9] else 0.0, reverse=True)
    except (ValueError, IndexError) as e:
        logger.error(f"按下载速度排序失败: {e}，保持原顺序")
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(final_rows)
    logger.info(f"去重并排序完成，{csv_file} 包含 {len(final_rows)} 条记录 (耗时: {time.time() - start_time:.2f} 秒)")

def generate_ips_file(csv_file: str):
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在，跳过生成 {IPS_FILE}")
        return
    country_cache = load_country_cache()
    final_nodes = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if len(row) < 2:
                continue
            ip, port = row[0], row[1]
            if not is_valid_ip(ip) or not is_valid_port(port):
                logger.debug(f"无效 IP 或端口: {ip}:{port}")
                continue
            country = get_country_from_ip(ip, country_cache)
            if country in DESIRED_COUNTRIES:
                final_nodes.append((ip, int(port), country))
            else:
                logger.debug(f"过滤掉 {ip}:{port}，国家 {country} 不在 {DESIRED_COUNTRIES}")
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
    labeled_nodes.sort(key=lambda x: (x[2].split('-')[0], int(x[2].split('-')[-1])))
    with open(IPS_FILE, "w", encoding="utf-8-sig") as f:
        for ip, port, label in labeled_nodes:
            f.write(f"{ip}:{port}#{label}\n")
    logger.info(f"生成 {IPS_FILE}，包含 {len(labeled_nodes)} 个节点 (耗时: {time.time() - start_time:.2f} 秒)")
    save_country_cache(country_cache)

def main():
    start_time = time.time()
    logger.info("脚本开始执行")
    check_dependencies()
    parser = argparse.ArgumentParser(description="IP Filter and Speed Test")
    parser.add_argument("--url", help="URL to fetch IP list", default=INPUT_URL)
    parser.add_argument("--target-nodes", type=int, default=500, help="Target number of nodes for ip.txt")
    parser.add_argument("--latency-threshold", type=float, default=500.0, help="Latency threshold in ms (0 to disable)")
    args = parser.parse_args()
    try:
        ip_ports = []
        if os.path.exists(INPUT_FILE):
            logger.info(f"尝试从本地文件 {INPUT_FILE} 获取 IP")
            ip_ports = extract_ip_ports_from_file(INPUT_FILE)
        else:
            logger.info(f"本地文件 {INPUT_FILE} 不存在，尝试从 URL {args.url} 获取 IP")
            temp_file = fetch_and_save_to_temp_file(args.url)
            if temp_file:
                ip_ports = extract_ip_ports_from_file(temp_file)
            else:
                logger.error("无法下载 URL 内容，退出")
                sys.exit(1)
        if not ip_ports:
            logger.error("未获取到有效的 IP 和端口，退出")
            logger.debug(f"检查 URL: {args.url}")
            sys.exit(1)
        logger.info(f"获取 IP 列表完成，解析到 {len(ip_ports)} 个节点 (耗时: {time.time() - start_time:.2f} 秒)")
        ip_list_file = write_ip_list(ip_ports, target_nodes=args.target_nodes, latency_threshold=args.latency_threshold)
        if not ip_list_file:
            logger.warning("生成 ip.txt 失败，继续生成空结果")
            # 继续执行，避免退出
        csv_file = run_speed_test()
        if not csv_file:
            logger.warning("测速失败，跳过后续步骤")
            return
        filter_speed_and_deduplicate(csv_file)
        generate_ips_file(csv_file)
        logger.info(f"脚本执行完成 (总耗时: {time.time() - start_time:.2f} 秒)")
    except Exception as e:
        logger.error(f"脚本执行异常: {str(e)}")
    finally:
        close_geoip_reader()

if __name__ == "__main__":
    main()
