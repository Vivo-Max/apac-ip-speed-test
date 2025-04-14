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
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import pandas as pd

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

# 配置常量
IP_LIST_FILE = "ip.txt"
IPS_FILE = "ips.txt"
FINAL_CSV = "ip.csv"
INPUT_FILE = "input.csv"
TEMP_FILE = os.path.join(tempfile.gettempdir(), "temp_proxy.csv")
TEMP_FILE_CACHE_DURATION = 3600
INPUT_URL = "https://raw.githubusercontent.com/gxiaobai2024/api/refs/heads/main/proxyip%20.csv"
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
REQUIRED_PACKAGES = ['requests', 'charset_normalizer', 'geoip2', 'beautifulsoup4', 'lxml', 'pandas']
ENABLE_PUSH = os.getenv("ENABLE_PUSH", "true").lower() == "true" and not os.getenv("GITHUB_ACTIONS")

# 国家标签和别名
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
    'PT': ('🇵🇹', '葡萄牙'), 'GR': ('🇬🇷', '希腊'), 'BG': ('🇬🇬', '保加利亚'),
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

# GeoIP 全局变量
geoip_reader = None

def download_geoip_database(url: str, dest_path: Path) -> bool:
    """下载 GeoIP 数据库"""
    try:
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, headers=HEADERS, stream=True, timeout=30)
        response.raise_for_status()
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info(f"GeoIP 数据库下载完成: {dest_path}")
        return True
    except Exception as e:
        logger.error(f"下载 GeoIP 数据库失败: {e}")
        return False

def download_geoip_database_maxmind(dest_path: Path) -> bool:
    """从 MaxMind 下载 GeoIP 数据库"""
    if not MAXMIND_LICENSE_KEY:
        logger.error("未提供 MAXMIND_LICENSE_KEY")
        return False
    url = GEOIP_DB_URL_BACKUP.format(MAXMIND_LICENSE_KEY)
    try:
        import tarfile
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, headers=HEADERS, stream=True, timeout=30)
        response.raise_for_status()
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz', mode='wb') as temp_tar:
            for chunk in response.iter_content(chunk_size=8192):
                temp_tar.write(chunk)
            temp_tar_path = temp_tar.name
        with tarfile.open(temp_tar_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("GeoLite2-Country.mmdb"):
                    tar.extract(member, dest_path.parent)
                    extracted_path = dest_path.parent / member.name
                    extracted_path.rename(dest_path)
                    logger.info(f"MaxMind GeoIP 数据库提取完成: {dest_path}")
                    os.remove(temp_tar_path)
                    return True
        logger.error("未找到 GeoLite2-Country.mmdb")
        os.remove(temp_tar_path)
        return False
    except Exception as e:
        logger.error(f"从 MaxMind 下载 GeoIP 数据库失败: {e}")
        if 'temp_tar_path' in locals():
            os.remove(temp_tar_path)
        return False

def init_geoip_reader():
    """初始化 GeoIP 数据库"""
    global geoip_reader
    update_interval = 7 * 24 * 3600  # 7 天
    
    def should_update_database(db_path: Path) -> bool:
        """检查是否需要更新 GeoIP 数据库"""
        if not db_path.exists():
            return True
        last_modified = db_path.stat().st_mtime
        if time.time() - last_modified > update_interval:
            logger.info("GeoIP 数据库超过 7 天未更新，检查远程版本")
            try:
                session = requests.Session()
                retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
                session.mount('https://', HTTPAdapter(max_retries=retries))
                response = session.head(GEOIP_DB_URL, headers=HEADERS, timeout=10)
                response.raise_for_status()
                remote_modified = response.headers.get('Last-Modified')
                if remote_modified:
                    from email.utils import parsedate_to_datetime
                    remote_time = parsedate_to_datetime(remote_modified).timestamp()
                    return remote_time > last_modified
                return True  # 无修改时间则强制更新
            except Exception as e:
                logger.warning(f"检查 GeoIP 更新失败: {e}")
                return False
        return False

    if should_update_database(GEOIP_DB_PATH):
        logger.info("GeoIP 数据库需要更新，尝试下载")
        if not download_geoip_database(GEOIP_DB_URL, GEOIP_DB_PATH):
            if not download_geoip_database_maxmind(GEOIP_DB_PATH):
                logger.error("无法下载 GeoIP 数据库")
                sys.exit(1)
    try:
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        logger.info("GeoIP 数据库初始化完成")
    except Exception as e:
        logger.error(f"初始化 GeoIP 数据库失败: {e}")
        sys.exit(1)

def close_geoip_reader():
    """关闭 GeoIP 数据库"""
    global geoip_reader
    if geoip_reader:
        try:
            geoip_reader.close()
            logger.info("GeoIP 数据库已关闭")
        except Exception as e:
            logger.warning(f"关闭 GeoIP 数据库失败: {e}")
        geoip_reader = None

atexit.register(close_geoip_reader)

def check_dependencies():
    """检查依赖"""
    missing_packages = []
    for pkg in REQUIRED_PACKAGES:
        if not importlib.util.find_spec(pkg):
            missing_packages.append(pkg)
    if missing_packages:
        logger.error(f"缺少以下依赖包: {', '.join(missing_packages)}. 请安装: pip install {' '.join(missing_packages)}")
        sys.exit(1)
    logger.info("所有依赖包已安装")
    init_geoip_reader()

def find_speedtest_script() -> str:
    """查找测速脚本并验证"""
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
            if candidate.endswith("iptest"):
                try:
                    with open(candidate, 'rb') as f:
                        magic = f.read(4)
                        if magic.startswith(b'\x7fELF') or magic.startswith(b'MZ'):
                            logger.info(f"确认 {candidate} 为有效二进制文件")
                            return candidate
                except Exception as e:
                    logger.warning(f"无法验证 {candidate} 的二进制格式: {e}")
                    continue
            logger.info(f"找到测速脚本: {candidate}")
            return candidate
    logger.error("未找到测速脚本 iptest.sh 或 iptest")
    sys.exit(1)

SPEEDTEST_SCRIPT = find_speedtest_script()

def load_country_cache() -> Dict[str, str]:
    """加载国家缓存"""
    try:
        if os.path.exists(COUNTRY_CACHE_FILE):
            with open(COUNTRY_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"加载国家缓存失败: {e}")
    return {}

def save_country_cache(cache: Dict[str, str]):
    """保存国家缓存"""
    try:
        with open(COUNTRY_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f"保存国家缓存失败: {e}")

def is_temp_file_valid(temp_file: str) -> bool:
    """检查临时文件有效性"""
    if not os.path.exists(temp_file):
        return False
    mtime = os.path.getmtime(temp_file)
    return (time.time() - mtime) < TEMP_FILE_CACHE_DURATION

def detect_delimiter(lines: List[str]) -> str:
    """检测 CSV 分隔符"""
    try:
        sample = '\n'.join(lines[:5])
        dialect = csv.Sniffer().sniff(sample)
        logger.info(f"检测到分隔符: {dialect.delimiter}")
        return dialect.delimiter
    except:
        comma_count = sum(1 for line in lines[:5] if ',' in line and line.strip())
        semicolon_count = sum(1 for line in lines[:5] if ';' in line and line.strip())
        tab_count = sum(1 for line in lines[:5] if '\t' in line and line.strip())
        space_count = sum(1 for line in lines[:5] if ' ' in line and line.strip())
        counts = [(comma_count, ','), (semicolon_count, ';'), (tab_count, '\t'), (space_count, ' ')]
        max_count, delimiter = max(counts, key=lambda x: x[0])
        logger.info(f"通过统计检测到分隔符: {delimiter}")
        return delimiter if max_count > 0 else ','

def is_valid_ip(ip: str) -> bool:
    """验证 IP 地址"""
    ip = ip.strip('[]')
    ipv4_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
    ipv6_pattern = r'^((?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})$'
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    if re.match(ipv6_pattern, ip):
        return True
    return False

def is_valid_port(port: str) -> bool:
    """验证端口"""
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def is_country_like(value: str) -> bool:
    """判断是否为国家代码或名称"""
    if not value:
        return False
    value_clean = re.sub(r'[^a-zA-Z\s]', '', value).strip().upper()
    if len(value_clean) == 2 and value_clean in COUNTRY_LABELS:
        return True
    if value_clean in COUNTRY_ALIASES:
        return True
    return False

def standardize_country(country: str) -> str:
    """标准化国家代码"""
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

def find_columns(lines: List[str], delimiter: str) -> Tuple[int, int, int]:
    """动态检测 IP、端口和国家列"""
    ip_col, port_col, country_col = -1, -1, -1
    sample_lines = [line for line in lines[:5] if line.strip() and not line.startswith('#')]
    if not sample_lines:
        logger.warning("无有效样本行，默认列: IP=0, Port=1, Country=-1")
        return 0, 1, -1

    header = sample_lines[0].strip().split(delimiter)
    ip_candidates = ['ip', 'address', 'ip_addr', 'host', 'server']
    port_candidates = ['port', '端口', 'port_num']
    country_candidates = ['country', '国家', 'code', 'location', 'nation', 'region']

    for idx, col in enumerate(header):
        col_lower = col.strip().lower()
        if any(cand in col_lower for cand in ip_candidates):
            ip_col = idx
        elif any(cand in col_lower for cand in port_candidates):
            port_col = idx
        elif any(cand in col_lower for cand in country_candidates):
            country_col = idx

    if ip_col == -1 or port_col == -1:
        col_matches = defaultdict(lambda: {'ip': 0, 'port': 0, 'country': 0})
        for line in sample_lines[1:]:
            fields = line.strip().split(delimiter)
            for col, field in enumerate(fields):
                field = field.strip()
                if is_valid_ip(field):
                    col_matches[col]['ip'] += 1
                elif is_valid_port(field):
                    col_matches[col]['port'] += 1
                elif is_country_like(field):
                    col_matches[col]['country'] += 1
        
        ip_scores = [(col, scores['ip']) for col, scores in col_matches.items()]
        port_scores = [(col, scores['port']) for col, scores in col_matches.items()]
        country_scores = [(col, scores['country']) for col, scores in col_matches.items()]
        
        if ip_scores:
            ip_col = max(ip_scores, key=lambda x: x[1])[0]
        if port_scores:
            port_col = max(port_scores, key=lambda x: x[1])[0]
        if country_scores:
            country_col = max(country_scores, key=lambda x: x[1])[0]

    ip_col = ip_col if ip_col != -1 else 0
    port_col = port_col if port_col != -1 else 1
    country_col = country_col if country_col != -1 else -1

    logger.info(f"检测到列: IP={ip_col}, Port={port_col}, Country={country_col}")
    return ip_col, port_col, country_col

def fetch_and_save_to_temp_file(url: str) -> str:
    """下载 URL 数据到临时文件"""
    logger.info(f"下载 URL: {url} 到临时文件")
    try:
        session = requests.Session()
        retries = Retry(total=10, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504, 530])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, timeout=60, headers=HEADERS, stream=True)
        response.raise_for_status()
        with tempfile.NamedTemporaryFile(delete=False, suffix='.csv', mode='wb') as temp_file:
            for chunk in response.iter_content(chunk_size=8192):
                temp_file.write(chunk)
            temp_file_path = temp_file.name
        logger.info(f"已下载到 {temp_file_path}")
        return temp_file_path
    except Exception as e:
        logger.error(f"下载 URL 失败: {e}")
        return ''

def parse_html_content(content: str) -> List[Tuple[str, int, str]]:
    """解析 HTML 表格中的 IP、端口和国家"""
    try:
        soup = BeautifulSoup(content, 'lxml')
        ip_ports = []
        for table in soup.find_all('table'):
            for row in table.find_all('tr'):
                cols = row.find_all('td')
                if len(cols) >= 2:
                    ip = cols[0].text.strip()
                    port = cols[1].text.strip()
                    country = cols[2].text.strip() if len(cols) > 2 else ''
                    if is_valid_ip(ip) and is_valid_port(port):
                        ip_ports.append((ip, int(port), standardize_country(country)))
        logger.info(f"从 HTML 解析到 {len(ip_ports)} 个节点")
        return ip_ports
    except Exception as e:
        logger.error(f"HTML 解析失败: {e}")
        return []

def parse_xml_content(content: str) -> List[Tuple[str, int, str]]:
    """解析 XML 中的 IP、端口和国家"""
    try:
        root = ET.fromstring(content)
        ip_ports = []
        for node in root.findall('.//proxy'):
            ip = node.find('ip').text.strip() if node.find('ip') is not None else ''
            port = node.find('port').text.strip() if node.find('port') is not None else ''
            country = node.find('country').text.strip() if node.find('country') is not None else ''
            if is_valid_ip(ip) and is_valid_port(port):
                ip_ports.append((ip, int(port), standardize_country(country)))
        logger.info(f"从 XML 解析到 {len(ip_ports)} 个节点")
        return ip_ports
    except Exception as e:
        logger.error(f"XML 解析失败: {e}")
        return []

def extract_ip_ports_from_file(file_path: str) -> List[Tuple[str, int, str]]:
    """从文件提取 IP、端口和国家"""
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
    """从内容提取 IP、端口和国家"""
    server_port_pairs = []
    invalid_lines = []
    content = content.replace('\r\n', '\n').replace('\r', '\n')
    lines = content.splitlines()
    if not lines:
        logger.error("内容为空")
        return []

    # HTML 解析
    if '<html' in content.lower() or '<table' in content.lower():
        return parse_html_content(content)

    # XML 解析
    if '<?xml' in content.lower() or '<proxy' in content.lower():
        return parse_xml_content(content)

    # JSON 解析
    try:
        data = json.loads(content)
        for item in data:
            ip = item.get('ip', '') or item.get('address', '') or item.get('host', '')
            port = item.get('port', '') or item.get('port_num', '')
            country = standardize_country(
                item.get('country', '') or item.get('countryCode', '') or item.get('location', '')
            )
            if is_valid_ip(ip) and is_valid_port(str(port)):
                server_port_pairs.append((ip, int(port), country))
        logger.info(f"从 JSON 解析到 {len(server_port_pairs)} 个节点")
        return list(dict.fromkeys(server_port_pairs))
    except json.JSONDecodeError:
        pass

    # CSV 或文本解析
    delimiter = detect_delimiter(lines)
    ip_col, port_col, country_col = find_columns(lines, delimiter)
    ip_port_pattern = re.compile(
        r'(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]|(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))[ :,\t](\d{1,5})'
    )

    lines_to_process = lines[1:] if lines and lines[0].strip() and not lines[0].startswith('#') else lines
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
            else:
                for col, field in enumerate(fields):
                    field = field.strip()
                    if is_country_like(field) or field.upper() in COUNTRY_ALIASES:
                        country = standardize_country(field)
                        break
            if is_valid_ip(server) and is_valid_port(port_str):
                server_port_pairs.append((server, int(port), country))
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid IP or port)")
        else:
            invalid_lines.append(f"Line {i}: {line} (No valid format)")

    if invalid_lines:
        logger.info(f"发现 {len(invalid_lines)} 个无效条目")
    logger.info(f"解析到 {len(server_port_pairs)} 个节点")
    unique_server_port_pairs = list(dict.fromkeys(server_port_pairs))
    logger.info(f"去重后: {len(unique_server_port_pairs)} 个节点")
    return unique_server_port_pairs

def get_country_from_ip(ip: str, cache: Dict[str, str]) -> str:
    """从 GeoIP 获取国家代码"""
    if ip in cache:
        return cache[ip]
    try:
        response = geoip_reader.country(ip)
        country_code = response.country.iso_code or ''
        if country_code:
            cache[ip] = country_code
            logger.debug(f"IP {ip}: GeoIP 查询国家 {country_code}")
            return country_code
        return ''
    except Exception as e:
        logger.debug(f"IP {ip}: GeoIP 查询失败: {e}")
        return ''

def write_ip_list(ip_ports: List[Tuple[str, int, str]]) -> str:
    """生成 ip.txt"""
    country_cache = load_country_cache()
    filtered_ip_ports = set()
    filtered_counts = defaultdict(int)
    invalid_nodes = 0

    for ip, port, country in ip_ports:
        if not is_valid_ip(ip) or not is_valid_port(str(port)):
            invalid_nodes += 1
            continue
        if not DESIRED_COUNTRIES:
            filtered_ip_ports.add((ip, port))
            country = country or get_country_from_ip(ip, country_cache)
        elif country and country in DESIRED_COUNTRIES:
            filtered_ip_ports.add((ip, port))
        elif country:
            filtered_counts[country] += 1
        else:
            country_from_geoip = get_country_from_ip(ip, country_cache)
            if country_from_geoip in DESIRED_COUNTRIES:
                filtered_ip_ports.add((ip, port))
            elif country_from_geoip:
                filtered_counts[country_from_geoip] += 1
            else:
                invalid_nodes += 1

    if filtered_counts:
        for country, count in filtered_counts.items():
            logger.info(f"过滤的国家 {country}: {count} 个节点")
    if invalid_nodes:
        logger.info(f"无效节点: {invalid_nodes} 个")
    logger.info(f"保留节点: {len(filtered_ip_ports)} 个")

    try:
        with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
            for ip, port in filtered_ip_ports:
                f.write(f"{ip} {port}\n")
        logger.info(f"{IP_LIST_FILE} 已生成，包含 {len(filtered_ip_ports)} 个节点")
        save_country_cache(country_cache)
        return IP_LIST_FILE
    except Exception as e:
        logger.error(f"写入 {IP_LIST_FILE} 失败: {e}")
        return ''

def run_speed_test(max_nodes: int = 0) -> str:
    """并行测速并实时保存结果"""
    if not SPEEDTEST_SCRIPT:
        logger.error("测速脚本未找到")
        return None
    if not os.path.exists(IP_LIST_FILE):
        logger.error(f"{IP_LIST_FILE} 不存在")
        return None

    start_time = time.time()
    try:
        with open(IP_LIST_FILE, "r", encoding="utf-8") as f:
            ip_lines = [line.strip().split() for line in f if line.strip()]
        ip_ports = [(ip, int(port)) for ip, port in ip_lines]
        total_nodes = len(ip_ports)
        if max_nodes > 0 and total_nodes > max_nodes:
            ip_ports = ip_ports[:max_nodes]
            total_nodes = max_nodes
            logger.info(f"限制测速节点数为 {max_nodes}")
        logger.info(f"{IP_LIST_FILE} 包含 {total_nodes} 个节点")
    except Exception as e:
        logger.error(f"读取 {IP_LIST_FILE} 失败: {e}")
        return None

    logger.info("开始并行测速")
    temp_csv = FINAL_CSV + ".tmp"
    results = []
    lock = threading.Lock()

    def test_ip(ip_port: Tuple[str, int]) -> Tuple[str, int, str]:
        ip, port = ip_port
        try:
            timeout = None if not os.getenv("GITHUB_ACTIONS") else 60
            process = subprocess.Popen(
                [SPEEDTEST_SCRIPT, f"{ip}:{port}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            stdout, stderr = process.communicate(timeout=timeout)
            with lock:
                for line in stdout.splitlines():
                    logger.info(f"[测速 {ip}:{port}] {line.strip()}")
                if stderr:
                    logger.warning(f"[测速 {ip}:{port} 错误] {stderr.strip()}")
                speed = re.search(r'speed: (\d+\.\d+)', stdout)
                speed_value = float(speed.group(1)) if speed else 0.0
                with open(temp_csv, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([ip, port, speed_value])
            return ip, port, stdout
        except subprocess.TimeoutExpired:
            process.kill()
            logger.warning(f"测速 {ip}:{port} 超时")
            return ip, port, ''
        except Exception as e:
            logger.error(f"测速 {ip}:{port} 失败: {e}")
            return ip, port, ''

    try:
        with open(temp_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "port", "speed"])

        max_workers = min(os.cpu_count() * 2, 8) if os.cpu_count() else 4
        logger.info(f"使用 {max_workers} 个线程进行测速")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(test_ip, ip_port) for ip_port in ip_ports]
            for future in futures:
                result = future.result()
                results.append(result)

        if os.path.exists(temp_csv) and os.path.getsize(temp_csv) > 10:
            os.rename(temp_csv, FINAL_CSV)
            logger.info(f"{FINAL_CSV} 已生成")
        else:
            logger.error(f"{FINAL_CSV} 未生成或内容无效")
            return None

        with open(FINAL_CSV, "r", encoding="utf-8") as f:
            lines = f.readlines()
            logger.info(f"{FINAL_CSV} 包含 {len(lines) - 1} 个节点")
        logger.info(f"测速完成，耗时: {time.time() - start_time:.2f} 秒")
        return FINAL_CSV
    except Exception as e:
        logger.error(f"并行测速异常: {e}")
        if os.path.exists(temp_csv):
            os.rename(temp_csv, FINAL_CSV)
            logger.info(f"保存部分测速结果到 {FINAL_CSV}")
            return FINAL_CSV
        return None
    finally:
        if os.path.exists(temp_csv):
            os.remove(temp_csv)

def filter_speed_and_deduplicate(csv_file: str):
    """去重并按速度排序"""
    try:
        df = pd.read_csv(csv_file)
        ip_col = next((col for col in df.columns if 'ip' in col.lower() or 'address' in col.lower()), df.columns[0])
        port_col = next((col for col in df.columns if 'port' in col.lower()), df.columns[1])
        speed_col = next((col for col in df.columns if 'speed' in col.lower() or 'rate' in col.lower()), df.columns[-1])
        df.drop_duplicates(subset=[ip_col, port_col], inplace=True)
        df.sort_values(by=speed_col, ascending=False, inplace=True)
        df.to_csv(csv_file, index=False)
        logger.info(f"{csv_file} 处理完成，{len(df)} 条记录")
    except Exception as e:
        logger.error(f"处理 {csv_file} 失败: {e}")

def generate_ips_file(csv_file: str):
    """生成 ips.txt"""
    country_cache = load_country_cache()
    final_nodes = []

    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            ip_col = next((i for i, col in enumerate(header) if 'ip' in col.lower() or 'address' in col.lower()), 0)
            port_col = next((i for i, col in enumerate(header) if 'port' in col.lower()), 1)
            for row in reader:
                if len(row) <= max(ip_col, port_col):
                    continue
                ip, port = row[ip_col], row[port_col]
                if not is_valid_ip(ip) or not is_valid_port(port):
                    continue
                country = get_country_from_ip(ip, country_cache)
                if not DESIRED_COUNTRIES or country in DESIRED_COUNTRIES:
                    final_nodes.append((ip, int(port), country))
    except Exception as e:
        logger.error(f"读取 {csv_file} 失败: {e}")
        return

    country_count = defaultdict(int)
    labeled_nodes = []
    for ip, port, country in sorted(final_nodes, key=lambda x: x[2] or 'ZZ'):
        if country:
            country_count[country] += 1
            emoji, name = COUNTRY_LABELS.get(country, ('🌐', '未知'))
            label = f"{emoji}{name}-{country_count[country]}"
            labeled_nodes.append((ip, port, label))
        else:
            labeled_nodes.append((ip, port, '🌐未知'))

    try:
        with open(IPS_FILE, "w", encoding="utf-8-sig") as f:
            for ip, port, label in labeled_nodes:
                f.write(f"{ip}:{port}#{label}\n")
        logger.info(f"{IPS_FILE} 已生成，包含 {len(labeled_nodes)} 个节点")
        save_country_cache(country_cache)
    except Exception as e:
        logger.error(f"写入 {IPS_FILE} 失败: {e}")

def commit_and_push_files():
    """提交并推送文件到 Git 仓库"""
    try:
        subprocess.run(["git", "config", "--global", "user.name", "Script Bot"], check=True)
        subprocess.run(["git", "config", "--global", "user.email", "bot@example.com"], check=True)
        
        files_to_commit = []
        for file in [IP_LIST_FILE, FINAL_CSV, IPS_FILE]:
            if os.path.exists(file):
                files_to_commit.append(file)
        
        if not files_to_commit:
            logger.info("无文件需要提交")
            return

        subprocess.run(["git", "add"] + files_to_commit, check=True)
        commit_result = subprocess.run(
            ["git", "commit", "-m", "Update ip.txt, ip.csv, ips.txt"],
            capture_output=True, text=True
        )
        if commit_result.returncode == 0:
            logger.info("文件已提交")
        else:
            logger.info("无变更需要提交")
            return

        pull_result = subprocess.run(
            ["git", "pull", "--rebase"],
            capture_output=True, text=True
        )
        if pull_result.returncode != 0:
            logger.warning(f"变基失败，尝试合并: {pull_result.stderr}")
            subprocess.run(["git", "rebase", "--abort"], capture_output=True)
            merge_result = subprocess.run(
                ["git", "merge", "origin/main", "-m", "Merge updates"],
                capture_output=True, text=True
            )
            if merge_result.returncode != 0:
                logger.error(f"合并失败: {merge_result.stderr}")
                force_push = subprocess.run(
                    ["git", "push", "--force"],
                    capture_output=True, text=True
                )
                if force_push.returncode == 0:
                    logger.info("强制推送成功")
                else:
                    logger.error(f"强制推送失败: {force_push.stderr}")
                    return
            else:
                subprocess.run(
                    ["git", "commit", "--allow-empty", "-m", "Resolve merge conflicts"],
                    capture_output=True, text=True
                )

        push_result = subprocess.run(
            ["git", "push"],
            capture_output=True, text=True
        )
        if push_result.returncode == 0:
            logger.info("文件已推送")
        else:
            logger.error(f"推送失败: {push_result.stderr}")
    except Exception as e:
        logger.error(f"Git 操作失败: {e}")

def main():
    """主函数"""
    start_time = time.time()
    logger.info("脚本开始")
    check_dependencies()

    parser = argparse.ArgumentParser(description="IP Filter and Speed Test")
    parser.add_argument("--generate-ips", action="store_true", help="仅记录日志，生成所有文件")
    parser.add_argument("--max-nodes", type=int, default=0, help="最大测速节点数，0 表示无限制")
    args = parser.parse_args()

    if args.generate_ips:
        logger.info("运行 --generate-ips 模式，生成所有文件")

    try:
        ip_ports = []
        input_urls = [
            INPUT_URL,
            "https://backup-url.com/proxy.csv"
        ]
        if os.path.exists(INPUT_FILE):
            logger.info(f"从 {INPUT_FILE} 获取节点")
            ip_ports = extract_ip_ports_from_file(INPUT_FILE)
        else:
            for url in input_urls:
                logger.info(f"未找到 {INPUT_FILE}，尝试从 URL {url} 下载")
                temp_file = fetch_and_save_to_temp_file(url)
                if temp_file:
                    ip_ports = extract_ip_ports_from_file(temp_file)
                    os.remove(temp_file)  # 清理临时文件
                    break
        if not ip_ports:
            logger.error("未获取到有效节点")
            sys.exit(1)
        ip_list_file = write_ip_list(ip_ports)
        if not ip_list_file:
            logger.error("生成 ip.txt 失败")
            sys.exit(1)

        csv_file = run_speed_test(max_nodes=args.max_nodes)
        if not csv_file:
            logger.error("测速失败")
            sys.exit(1)

        filter_speed_and_deduplicate(csv_file)
        generate_ips_file(csv_file)

        if ENABLE_PUSH:
            commit_and_push_files()

        logger.info(f"脚本完成 (总耗时: {time.time() - start_time:.2f} 秒)")
    except Exception as e:
        logger.error(f"脚本异常: {e}")
        sys.exit(1)
    finally:
        close_geoip_reader()

if __name__ == "__main__":
    main()
