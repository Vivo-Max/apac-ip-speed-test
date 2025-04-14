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
from typing import List, Tuple, Dict
from collections import defaultdict
from charset_normalizer import detect
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import geoip2.database
from pathlib import Path
import tempfile
import atexit

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("speedtest.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
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
INPUT_URL = "https://bihai.cf/CFIP/CUCC/standard.csv"
COUNTRY_CACHE_FILE = "country_cache.json"
GEOIP_DB_PATH = Path("GeoLite2-Country.mmdb")
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
    'MN': ('🇲🇳', '蒙古'), 'KP': ('🇵🇵', '朝鲜'), 'US': ('🇺🇸', '美国'),
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
    'PT': ('🇵🇹', '葡萄牙'), 'GR': ('🇬🇷', '希腊'), 'BG': ('🇧🇬', '保加利亚'),
    'SK': ('🇸🇰', '斯洛伐克'), 'SI': ('🇸🇮', '斯洛文尼亚'), 'HR': ('🇭🇷', '克罗地亚'),
    'RS': ('🇷🇸', '塞尔维亚'), 'BA': ('🇧🇦', '波黑'), 'MK': ('🇲🇰', '北马其顿'),
    'AL': ('🇦🇱', '阿尔巴尼亚'), 'KZ': ('🇰🇿', '哈萨克斯坦'), 'UZ': ('🇺🇿', '乌兹别克斯坦'),
    'KG': ('🇰🇬', '吉尔吉斯斯坦'), 'TJ': ('🇯🇯', '塔吉克斯坦'), 'TM': ('🇹🇲', '土库曼斯坦'),
    'GE': ('🇬🇪', '格鲁吉亚'), 'AM': ('🇦🇲', '亚美尼亚'), 'AZ': ('🇦🇿', '阿塞拜疆'),
    'KW': ('🇰🇼', '科威特'), 'BH': ('🇧🇭', '巴林'), 'OM': ('🇴🇲', '阿曼'),
    'JO': ('🇯🇴', '约旦'), 'LB': ('🇱🇧', '黎巴嫩'), 'SY': ('🇸🇾', '叙利亚'),
    'IQ': ('🇮🇶', '伊拉克'), 'YE': ('🇾🇪', '也门'),
    'EE': ('🇪🇪', '爱沙尼亚'), 'LV': ('🇱🇻', '拉脱维亚'), 'LT': ('🇱🇹', '立陶宛')
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
            logger.info(f"找到测速脚本: {candidate}")
            return candidate
    logger.warning("未找到测速脚本，请确保 iptest.sh 或 iptest 存在")
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
        response = session.get(url, timeout=60, stream=True, headers=HEADERS)
        response.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info(f"GeoIP 数据库下载完成: {dest_path}")
        if not dest_path.exists() or dest_path.stat().st_size < 100:
            logger.error(f"下载的 GeoIP 数据库无效")
            dest_path.unlink(missing_ok=True)
            return False
        try:
            with geoip2.database.Reader(dest_path) as reader:
                pass
        except Exception as e:
            logger.error(f"GeoIP 数据库损坏: {e}")
            dest_path.unlink(missing_ok=True)
            return False
        return True
    except Exception as e:
        logger.error(f"下载 GeoIP 数据库失败: {e}")
        return False

def download_geoip_database_maxmind(dest_path: Path) -> bool:
    if not MAXMIND_LICENSE_KEY:
        logger.warning("无 MAXMIND_LICENSE_KEY，跳过 MaxMind 下载")
        return False
    url = GEOIP_DB_URL_BACKUP.format(MAXMIND_LICENSE_KEY)
    logger.info(f"从 MaxMind 下载 GeoIP 数据库: {url}")
    try:
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504, 429])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, timeout=60, stream=True, headers=HEADERS)
        response.raise_for_status()
        temp_tar = dest_path.with_suffix(".tar.gz")
        with open(temp_tar, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
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
            logger.error(f"解压的 GeoIP 数据库无效")
            dest_path.unlink(missing_ok=True)
            return False
        try:
            with geoip2.database.Reader(dest_path) as reader:
                pass
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
    if not GEOIP_DB_PATH.exists():
        logger.warning(f"GeoIP 数据库 {GEOIP_DB_PATH} 不存在，尝试下载")
        if not download_geoip_database(GEOIP_DB_URL, GEOIP_DB_PATH):
            logger.warning("主下载源失败，尝试 MaxMind")
            if not download_geoip_database_maxmind(GEOIP_DB_PATH):
                logger.error("无法下载 GeoIP 数据库")
                sys.exit(1)
    try:
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        logger.info("GeoIP 数据库加载成功")
    except Exception as e:
        logger.error(f"GeoIP 数据库加载失败: {e}")
        GEOIP_DB_PATH.unlink(missing_ok=True)
        if not download_geoip_database(GEOIP_DB_URL, GEOIP_DB_PATH):
            logger.warning("主下载源失败，尝试 MaxMind")
            if not download_geoip_database_maxmind(GEOIP_DB_PATH):
                logger.error("重新下载 GeoIP 数据库失败")
                sys.exit(1)
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

def close_geoip_reader():
    global geoip_reader
    if geoip_reader:
        geoip_reader.close()
        geoip_reader = None
        logger.info("GeoIP 数据库已关闭")

atexit.register(close_geoip_reader)

def check_dependencies():
    for pkg in REQUIRED_PACKAGES:
        if not importlib.util.find_spec(pkg):
            logger.error(f"缺少依赖包: {pkg}")
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
        logger.info(f"临时文件 {temp_file} 已过期")
        return False
    if os.path.getsize(temp_file) < 10:
        logger.warning(f"临时文件 {temp_file} 内容过小")
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
    ipv4_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
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
        return country_clean
    if country_clean in COUNTRY_ALIASES:
        return COUNTRY_ALIASES[country_clean]
    country_clean = country_clean.replace(' ', '')
    for alias, code in COUNTRY_ALIASES.items():
        alias_clean = alias.replace(' ', '')
        if country_clean == alias_clean:
            return code
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
            logger.info(f"国家列: 第 {country_col + 1} 列 (匹配率: {match_rate:.2%})")

    return ip_col, port_col, country_col

def fetch_and_save_to_temp_file(url: str) -> str:
    logger.info(f"下载 URL: {url} 到 {TEMP_FILE}")
    try:
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=2, status_forcelist=[500, 502, 503, 504, 429])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, timeout=60, headers=HEADERS, stream=True)
        response.raise_for_status()
        with open(TEMP_FILE, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info(f"已下载到 {TEMP_FILE}")
        return TEMP_FILE
    except Exception as e:
        logger.error(f"下载 URL 失败: {e}")
        return ''

def extract_ip_ports_from_file(file_path: str) -> List[Tuple[str, int, str]]:
    if not os.path.exists(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []
    start_time = time.time()
    with open(file_path, "rb") as f:
        raw_data = f.read()
    encoding = detect(raw_data).get("encoding", "utf-8")
    try:
        content = raw_data.decode(encoding)
    except UnicodeDecodeError as e:
        logger.error(f"无法解码文件 {file_path}: {e}")
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
        logger.error("内容为空")
        return []

    # 保存数据源样本便于调试
    logger.debug(f"数据源样本（前5行）：{lines[:5]}")

    # 尝试 JSON 格式
    try:
        data = json.loads(content)
        for item in data:
            ip = item.get('ip', '')
            port = item.get('port', '')
            country = standardize_country(
                item.get('country', '') or
                item.get('countryCode', '') or
                item.get('country_code', '') or
                item.get('location', '') or
                item.get('nation', '') or
                item.get('region', '') or
                item.get('geo', '') or
                item.get('area', '')
            )
            if is_valid_ip(ip) and is_valid_port(str(port)):
                server_port_pairs.append((ip, int(port), country))
        logger.info(f"从 JSON 解析到 {len(server_port_pairs)} 个节点，其中 {sum(1 for _, _, c in server_port_pairs if c)} 个有国家信息")
        return list(dict.fromkeys(server_port_pairs))
    except json.JSONDecodeError:
        pass

    # 检测分隔符
    delimiter = detect_delimiter(lines)
    if not delimiter:
        logger.warning("无法检测分隔符，假设为逗号")
        delimiter = ','

    # 尝试检测表头中的国家列
    ip_col, port_col, country_col = 0, 1, -1
    lines_to_process = lines
    if lines and lines[0].strip() and not lines[0].startswith('#'):
        header = lines[0].strip().split(delimiter)
        logger.debug(f"检测到表头：{header}")
        for idx, col in enumerate(header):
            col_lower = col.strip().lower()
            if col_lower in ['ip', 'address', 'ip_address', 'ip地址']:
                ip_col = idx
            elif col_lower in ['port', '端口', 'port_number', '端口号']:
                port_col = idx
            elif col_lower in ['country', '国家', 'country_code', 'countrycode', '国际代码', 'nation', 'location', 'region', 'geo', 'area']:
                country_col = idx
        if country_col != -1:
            logger.info(f"检测到国家列：第 {country_col + 1} 列（字段名：{header[country_col]}）")
            lines_to_process = lines[1:]
        else:
            logger.info("表头未包含国家列，将遍历每行每列查找国家信息")

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
            port = match.group(4)
            country = ''
            if delimiter and country_col != -1:
                fields = line.split(delimiter)
                if country_col < len(fields):
                    country = standardize_country(fields[country_col].strip())
            if not country and delimiter:
                fields = line.split(delimiter)
                for col, field in enumerate(fields):
                    field = field.strip()
                    potential_country = standardize_country(field)
                    if potential_country:
                        country = potential_country
                        logger.debug(f"Line {i}: 国家信息从第 {col + 1} 列提取：{field} -> {country}")
                        break
            if is_valid_port(port):
                server_port_pairs.append((server, int(port), country))
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid port)")
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
            if not country:
                fields = line.split(delimiter)
                for col, field in enumerate(fields):
                    field = field.strip()
                    potential_country = standardize_country(field)
                    if potential_country:
                        country = potential_country
                        logger.debug(f"Line {i}: 国家信息从第 {col + 1} 列提取：{field} -> {country}")
                        break
            if is_valid_ip(server) and is_valid_port(port_str):
                server_port_pairs.append((server, int(port_str), country))
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid IP or port)")
        else:
            invalid_lines.append(f"Line {i}: {line} (No valid format)")

    if invalid_lines:
        logger.info(f"发现 {len(invalid_lines)} 个无效条目")
    logger.info(f"解析到 {len(server_port_pairs)} 个节点，其中 {sum(1 for _, _, c in server_port_pairs if c)} 个有国家信息")
    unique_server_port_pairs = list(dict.fromkeys(server_port_pairs))
    logger.info(f"去重后: {len(unique_server_port_pairs)} 个节点")
    return unique_server_port_pairs

def get_country_from_ip(ip: str, cache: Dict[str, str]) -> str:
    if ip in cache:
        return cache[ip]
    try:
        response = geoip_reader.country(ip)
        country_code = response.country.iso_code or ''
        if country_code:
            cache[ip] = country_code
            return country_code
        return ''
    except Exception:
        return ''

def get_countries_from_ips(ips: List[str], cache: Dict[str, str]) -> List[str]:
    uncached_ips = [ip for ip in ips if ip not in cache]
    if uncached_ips:
        logger.info(f"批量查询 {len(uncached_ips)} 个 IP 的国家信息")
        for ip in uncached_ips:
            try:
                response = geoip_reader.country(ip)
                cache[ip] = response.country.iso_code or ''
            except Exception:
                cache[ip] = ''
    return [cache[ip] for ip in ips]

def write_ip_list(ip_ports: List[Tuple[str, int, str]]) -> str:
    if not ip_ports:
        logger.error(f"无有效节点，无法生成 {IP_LIST_FILE}")
        return None

    start_time = time.time()
    country_cache = load_country_cache()
    filtered_ip_ports = set()
    country_counts = defaultdict(int)
    filtered_counts = defaultdict(int)
    logger.info(f"开始处理 {len(ip_ports)} 个节点...")

    from_source = sum(1 for _, _, country in ip_ports if country)
    logger.info(f"数据源提供国家信息: {from_source} 个节点")

    supplemented = 0
    for ip, port, country in ip_ports:
        final_country = country
        source = "数据源" if country else "待查询"
        
        if not country:
            final_country = get_country_from_ip(ip, country_cache)
            if final_country:
                supplemented += 1
                source = "GeoIP 数据库"
        
        logger.debug(f"IP {ip}:{port} 国家: {final_country} (来源: {source})")

        if not DESIRED_COUNTRIES:
            filtered_ip_ports.add((ip, port))
            if final_country:
                country_counts[final_country] += 1
        elif final_country and final_country in DESIRED_COUNTRIES:
            filtered_ip_ports.add((ip, port))
            country_counts[final_country] += 1
        else:
            filtered_counts[final_country or 'UNKNOWN'] += 1

    total_retained = len(filtered_ip_ports)
    total_filtered = sum(filtered_counts.values())
    logger.info(f"筛选结果：保留 {total_retained} 个节点，过滤 {total_filtered} 个节点")
    logger.info(f"通过 GeoIP 数据库补充国家信息: {supplemented} 个节点")
    logger.info(f"保留国家分布：{dict(country_counts)}")
    logger.info(f"过滤国家分布：{dict(filtered_counts)}")

    if not filtered_ip_ports:
        logger.error(f"无有效节点生成 {IP_LIST_FILE}")
        return None

    with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
        for ip, port in filtered_ip_ports:
            f.write(f"{ip} {port}\n")
    logger.info(f"生成 {IP_LIST_FILE}，包含 {len(filtered_ip_ports)} 个节点（耗时：{time.time() - start_time:.2f} 秒）")
    save_country_cache(country_cache)
    return IP_LIST_FILE

def run_speed_test() -> str:
    if not SPEEDTEST_SCRIPT:
        logger.error("测速脚本未找到")
        return None
    if not os.path.exists(IP_LIST_FILE):
        logger.error(f"{IP_LIST_FILE} 不存在")
        return None

    start_time = time.time()
    try:
        with open(IP_LIST_FILE, "r", encoding="utf-8") as f:
            ip_lines = [line.strip() for line in f if line.strip()]
        total_nodes = len(ip_lines)
        logger.info(f"{IP_LIST_FILE} 包含 {total_nodes} 个节点")
    except Exception as e:
        logger.error(f"读取 {IP_LIST_FILE} 失败: {e}")
        return None

    logger.info("开始测速")
    try:
        process = subprocess.Popen(
            [SPEEDTEST_SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,
            encoding='utf-8',
            errors='replace'
        )
        stdout_lines, stderr_lines = [], []
        def read_stream(stream, lines):
            while True:
                line = stream.readline()
                if not line:
                    break
                lines.append(line)
                logger.debug(line.strip())
        stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, stdout_lines))
        stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, stderr_lines))
        stdout_thread.start()
        stderr_thread.start()

        return_code = process.wait()
        stdout_thread.join()
        stderr_thread.join()
        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)
        if stdout:
            logger.info(f"测速输出: {stdout}")
        if stderr:
            logger.warning(f"测速错误: {stderr}")

        logger.info(f"测速完成，耗时: {time.time() - start_time:.2f} 秒")
        if return_code != 0:
            logger.error(f"测速失败，返回码: {return_code}")
            return None
        if not os.path.exists(FINAL_CSV) or os.path.getsize(FINAL_CSV) < 10:
            logger.error(f"{FINAL_CSV} 未生成或内容无效")
            return None
        with open(FINAL_CSV, "r", encoding="utf-8") as f:
            lines = f.readlines()
            node_count = len(lines) - 1 if lines else 0
            logger.info(f"{FINAL_CSV} 包含 {node_count} 个节点")
        return FINAL_CSV
    except Exception as e:
        logger.error(f"测速异常: {e}")
        return None

def filter_speed_and_deduplicate(csv_file: str):
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在")
        return
    seen = set()
    final_rows = []
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                logger.error(f"{csv_file} 无有效表头")
                return
            for row in reader:
                if len(row) < 2:
                    continue
                key = (row[0], row[1])
                if key not in seen:
                    seen.add(key)
                    final_rows.append(row)
    except Exception as e:
        logger.error(f"处理 {csv_file} 失败: {e}")
        return
    if not final_rows:
        logger.info(f"无有效节点")
        os.remove(csv_file)
        return
    try:
        final_rows.sort(key=lambda x: float(x[9]) if len(x) > 9 and x[9] and x[9].replace('.', '', 1).isdigit() else 0.0, reverse=True)
    except Exception as e:
        logger.warning(f"排序失败: {e}")
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(final_rows)
    logger.info(f"{csv_file} 处理完成，{len(final_rows)} 个数据节点 (耗时: {time.time() - start_time:.2f} 秒)")
    return len(final_rows)

def generate_ips_file(csv_file: str):
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在")
        return
    country_cache = load_country_cache()
    final_nodes = []
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                if len(row) < 2:
                    continue
                ip, port = row[0], row[1]
                if not is_valid_ip(ip) or not is_valid_port(port):
                    continue
                country = country_cache.get(ip, '')
                if not country:
                    country = get_country_from_ip(ip, country_cache)
                if not DESIRED_COUNTRIES or country in DESIRED_COUNTRIES:
                    final_nodes.append((ip, int(port), country))
    except Exception as e:
        logger.error(f"读取 {csv_file} 失败: {e}")
        return
    if not final_nodes:
        logger.info(f"无符合条件的节点")
        return
    country_count = defaultdict(int)
    labeled_nodes = []
    for ip, port, country in sorted(final_nodes, key=lambda x: x[2] or 'ZZ'):
        if country:
            country_count[country] += 1
            emoji, name = COUNTRY_LABELS.get(country, ('🌐', '未知'))
            label = f"{emoji}{name}-{country_count[country]}"
            labeled_nodes.append((ip, port, label))
    with open(IPS_FILE, "w", encoding="utf-8-sig") as f:
        for ip, port, label in labeled_nodes:
            f.write(f"{ip}:{port}#{label}\n")
    logger.info(f"生成 {IPS_FILE}，{len(labeled_nodes)} 个数据节点 (耗时: {time.time() - start_time:.2f} 秒)")
    logger.info(f"国家分布：{dict(country_count)}")
    save_country_cache(country_cache)
    return len(labeled_nodes)

def detect_environment() -> tuple[str, bool]:
    is_github_actions = os.getenv("GITHUB_ACTIONS") == "true"
    try:
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
    except subprocess.CalledProcessError:
        branch = "main"
        logger.warning(f"无法检测当前分支，使用默认分支: {branch}")
    return branch, is_github_actions

def push_to_repository(files_to_commit: List[str], branch: str, is_github_actions: bool):
    if not files_to_commit:
        logger.info("无文件需要推送")
        return

    try:
        subprocess.run(["git", "config", "--global", "user.name", "GitHub Actions Bot"], check=True)
        subprocess.run(["git", "config", "--global", "user.email", "actions@github.com"], check=True)

        if is_github_actions:
            repo_url = f"https://{os.environ['GITHUB_ACTOR']}:{os.environ['GITHUB_TOKEN']}@github.com/{os.environ['GITHUB_REPOSITORY']}.git"
            subprocess.run(["git", "remote", "set-url", "origin", repo_url], check=True)
        else:
            try:
                remote_url = subprocess.run(
                    ["git", "remote", "get-url", "origin"],
                    capture_output=True,
                    text=True,
                    check=True
                ).stdout.strip()
                if not remote_url:
                    raise subprocess.CalledProcessError(1, "git remote get-url")
            except subprocess.CalledProcessError:
                logger.warning("本地环境未检测到远程仓库，跳过推送")
                return
            logger.info(f"本地环境：使用远程仓库 {remote_url}")

        # 检查工作目录状态
        status_result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True
        )
        if status_result.stdout:
            logger.warning(f"工作目录有未暂存更改：\n{status_result.stdout}")
            # 清理未跟踪文件
            subprocess.run(["git", "clean", "-fd"], check=True)
            # 重置已跟踪文件的更改
            subprocess.run(["git", "reset", "--hard"], check=True)
            # 再次检查工作目录
            status_result = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True,
                text=True,
                check=True
            )
            if status_result.stdout:
                logger.error(f"工作目录清理后仍有更改：\n{status_result.stdout}")
                raise RuntimeError("无法清理工作目录")

        # 拉取最新代码并变基
        pull_result = subprocess.run(
            ["git", "pull", "--rebase", "origin", branch],
            capture_output=True,
            text=True,
            check=True
        )
        logger.debug(f"Git pull output: {pull_result.stdout}")

        # 添加目标文件
        files_added = []
        for file in files_to_commit:
            if os.path.exists(file):
                subprocess.run(["git", "add", file], check=True)
                files_added.append(file)
            else:
                logger.warning(f"文件 {file} 不存在，跳过添加")
        if not files_added:
            logger.info("无文件可提交")
            return

        commit_msg = "Update ip.txt, ip.csv, and ips.txt with speed test results"
        commit_result = subprocess.run(
            ["git", "commit", "-m", commit_msg],
            capture_output=True,
            text=True
        )
        if commit_result.returncode == 0:
            logger.info("文件已提交")
        else:
            logger.warning("无新更改需要提交，可能文件未变更")
            return

        # 推送
        push_result = subprocess.run(
            ["git", "push", "origin", f"HEAD:{branch}"],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(f"成功推送 {', '.join(files_added)} 到分支 {branch}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Git 操作失败: {e.stderr if e.stderr else e.stdout}")
        logger.error(f"完整错误输出: {e.output}")
        raise
    except Exception as e:
        logger.error(f"推送过程中发生异常: {e}")
        raise

def main():
    start_time = time.time()
    logger.info("脚本开始")
    check_dependencies()
    parser = argparse.ArgumentParser(description="IP Filter and Speed Test")
    parser.add_argument("--generate-ips", action="store_true")
    args = parser.parse_args()

    branch, is_github_actions = detect_environment()
    logger.info(f"运行环境: {'GitHub Actions' if is_github_actions else '本地服务器'}，分支: {branch}")

    try:
        files_to_commit = []
        
        if not args.generate_ips:
            ip_ports = []
            if os.path.exists(INPUT_FILE):
                logger.info(f"从 {INPUT_FILE} 获取节点")
                ip_ports = extract_ip_ports_from_file(INPUT_FILE)
            else:
                logger.info(f"未找到 {INPUT_FILE}，从 URL {INPUT_URL} 下载")
                temp_file = fetch_and_save_to_temp_file(INPUT_URL)
                if temp_file:
                    ip_ports = extract_ip_ports_from_file(temp_file)
            if not ip_ports:
                logger.error("未获取到有效节点")
                sys.exit(1)
            ip_list_file = write_ip_list(ip_ports)
            if not ip_list_file:
                sys.exit(1)
            files_to_commit.append(IP_LIST_FILE)
        else:
            csv_file = run_speed_test()
            if not csv_file:
                sys.exit(1)
            node_count = filter_speed_and_deduplicate(csv_file)
            if node_count is None:
                sys.exit(1)
            generate_ips_file(csv_file)
            if os.path.exists(FINAL_CSV):
                files_to_commit.append(FINAL_CSV)
            if os.path.exists(IPS_FILE):
                files_to_commit.append(IPS_FILE)
            if os.path.exists(IP_LIST_FILE):
                files_to_commit.append(IP_LIST_FILE)

            if files_to_commit and is_github_actions:
                push_to_repository(files_to_commit, branch, is_github_actions)
            else:
                logger.info("本地运行或无文件可推送，跳过推送")

        logger.info(f"脚本完成 (总耗时: {time.time() - start_time:.2f} 秒)")
    finally:
        close_geoip_reader()

if __name__ == "__main__":
    main()
