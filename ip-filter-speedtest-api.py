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
    'TW': ('🇹🇼', '台湾'), 'HK': ('🇭🇰', '香港'), 'VN': ('🇻🇳', '越南'),
    'IN': ('🇮🇳', '印度'), 'KP': ('🇰🇵', '朝鲜'), 'TH': ('🇹🇭', '泰国'),
    'MM': ('🇲🇲', '缅甸')
}
COUNTRY_ALIASES = {
    'SOUTH KOREA': 'KR', 'KOREA': 'KR', 'REPUBLIC OF KOREA': 'KR', 'KOREA, REPUBLIC OF': 'KR',
    'HONG KONG': 'HK', 'HONGKONG': 'HK', 'HK SAR': 'HK',
    'JAPAN': 'JP', 'JPN': 'JP', '日本': 'JP',
    'TAIWAN': 'TW', 'TWN': 'TW', 'TAIWAN, PROVINCE OF CHINA': 'TW', '台湾': 'TW',
    'SINGAPORE': 'SG', 'SGP': 'SG', '新加坡': 'SG',
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
    sys.exit(1)

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
            logger.error(f"GeoIP 数据库损坏: {e}")
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
    try:
        data = json.loads(content)
        for item in data:
            ip = item.get('ip', '')
            port = item.get('port', '')
            country = standardize_country(item.get('country', '') or item.get('countryCode', '') or item.get('location', ''))
            if is_valid_ip(ip) and is_valid_port(str(port)):
                server_port_pairs.append((ip, int(port), country))
        logger.info(f"从 JSON 解析到 {len(server_port_pairs)} 个节点")
        return list(dict.fromkeys(server_port_pairs))
    except json.JSONDecodeError:
        pass

    delimiter = detect_delimiter(lines)
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
            lines_to_process = lines[1:]
        else:
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
                server_port_pairs.append((server, int(port_str), country))
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

def write_ip_list(ip_ports: List[Tuple[str, int, str]]) -> str:
    """写入 ip.txt，保留所有符合条件的节点"""
    if not ip_ports:
        logger.error(f"无有效节点，无法生成 {IP_LIST_FILE}")
        return None

    start_time = time.time()
    country_cache = load_country_cache()
    filtered_ip_ports = []
    country_counts = defaultdict(int)
    filtered_counts = defaultdict(int)
    soft_max_nodes = 2000  # 软上限，防极端情况
    logger.info(f"筛选 {len(ip_ports)} 个节点")

    for ip, port, country in ip_ports:
        if country and country in DESIRED_COUNTRIES:
            filtered_ip_ports.append((ip, port))
            country_counts[country] += 1
        elif country:
            filtered_counts[country] += 1
        else:
            country_from_geoip = get_country_from_ip(ip, country_cache)
            if country_from_geoip in DESIRED_COUNTRIES:
                filtered_ip_ports.append((ip, port))
                country_counts[country_from_geoip] += 1
            else:
                filtered_counts[country_from_geoip] += 1

    logger.info(f"保留国家: {dict(country_counts)}")
    logger.info(f"过滤国家: {dict(filtered_counts)}")

    # 软上限
    if len(filtered_ip_ports) > soft_max_nodes:
        logger.warning(f"节点数 {len(filtered_ip_ports)} 超软上限 {soft_max_nodes}，随机采样")
        filtered_ip_ports = random.sample(filtered_ip_ports, soft_max_nodes)
        country_counts = defaultdict(int)
        for ip, port in filtered_ip_ports:
            country = get_country_from_ip(ip, country_cache)
            if country in DESIRED_COUNTRIES:
                country_counts[country] += 1
        logger.info(f"采样后: {len(filtered_ip_ports)} 节点，国家分布: {dict(country_counts)}")

    if not filtered_ip_ports:
        logger.error(f"无符合 {DESIRED_COUNTRIES} 的节点")
        return None

    with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
        for ip, port in filtered_ip_ports:
            f.write(f"{ip} {port}\n")
    logger.info(f"生成 {IP_LIST_FILE}，{len(filtered_ip_ports)} 个节点 (耗时: {time.time() - start_time:.2f} 秒)")
    save_country_cache(country_cache)
    return IP_LIST_FILE

def run_speed_test() -> str:
    """分批运行测速，控制总时间"""
    if not SPEEDTEST_SCRIPT:
        logger.error("测速脚本未找到")
        return None
    if not os.path.exists(IP_LIST_FILE):
        logger.error(f"{IP_LIST_FILE} 不存在")
        return None

    start_time = time.time()
    batch_size = 20
    max_time_seconds = 480  # 8 分钟
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
        batch_start_time = time.time()
        try:
            cmd = [
                SPEEDTEST_SCRIPT,
                f"-file={batch_file}",
                "-tls=true",
                "-speedtest=3",
                "-speedlimit=10",
                "-url=speed.cloudflare.com/__down?bytes=1000000",
                "-max=10",
                "-timeout=10",
                f"-outfile={batch_output}"
            ]
            logger.info(f"批次 {i//batch_size + 1} 命令: {' '.join(cmd)}")
            process = subprocess.Popen(
                ' '.join(cmd),
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
                logger.error(f"批次 {i//batch_size + 1} 失败")
        except subprocess.TimeoutExpired:
            logger.error(f"批次 {i//batch_size + 1} 超时")
            process.kill()
        except Exception as e:
            logger.error(f"批次 {i//batch_size + 1} 失败: {e}")

    if output_files:
        with open(FINAL_CSV, "w", encoding="utf-8") as outfile:
            for idx, batch_output in enumerate(output_files):
                with open(batch_output, "r", encoding="utf-8") as infile:
                    if idx == 0:
                        outfile.write(infile.read())
                    else:
                        lines = infile.readlines()[1:]
                        outfile.writelines(lines)
        logger.info(f"合并 {len(output_files)} 个批次到 {FINAL_CSV}")
        return FINAL_CSV
    logger.error("所有批次测速失败")
    return None

def filter_speed_and_deduplicate(csv_file: str):
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在")
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
        logger.info(f"无有效节点")
        os.remove(csv_file)
        return
    try:
        final_rows.sort(key=lambda x: float(x[9]) if x[9] else 0.0, reverse=True)
    except Exception as e:
        logger.warning(f"排序失败: {e}")
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(final_rows)
    logger.info(f"{csv_file} 处理完成，{len(final_rows)} 条记录 (耗时: {time.time() - start_time:.2f} 秒)")

def generate_ips_file(csv_file: str):
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在")
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
                continue
            country = get_country_from_ip(ip, country_cache)
            if country in DESIRED_COUNTRIES:
                final_nodes.append((ip, int(port), country))
    if not final_nodes:
        logger.info(f"无符合条件的节点")
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
    logger.info(f"生成 {IPS_FILE}，{len(labeled_nodes)} 个节点 (耗时: {time.time() - start_time:.2f} 秒)")
    save_country_cache(country_cache)

def main():
    start_time = time.time()
    logger.info("脚本开始")
    check_dependencies()
    parser = argparse.ArgumentParser(description="IP Filter and Speed Test")
    parser.add_argument("--url", default=INPUT_URL)
    args = parser.parse_args()
    try:
        ip_ports = []
        if os.path.exists(INPUT_FILE):
            logger.info(f"从 {INPUT_FILE} 获取节点")
            ip_ports = extract_ip_ports_from_file(INPUT_FILE)
        else:
            logger.info(f"未找到 {INPUT_FILE}，从 URL {args.url} 下载")
            temp_file = fetch_and_save_to_temp_file(args.url)
            if temp_file:
                ip_ports = extract_ip_ports_from_file(temp_file)
        if not ip_ports:
            logger.error("未获取到有效节点")
            sys.exit(1)
        ip_list_file = write_ip_list(ip_ports)
        if not ip_list_file:
            sys.exit(1)
        csv_file = run_speed_test()
        if not csv_file:
            sys.exit(1)
        filter_speed_and_deduplicate(csv_file)
        generate_ips_file(csv_file)
        logger.info(f"脚本完成 (总耗时: {time.time() - start_time:.2f} 秒)")
    finally:
        close_geoip_reader()

if __name__ == "__main__":
    main()
