import argparse
import csv
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import importlib.util
import requests
from collections import Counter
from pathlib import Path
from typing import List, Tuple, Optional, Dict
from urllib3.util.retry import Retry
from geoip2.database import Reader
from geoip2.errors import GeoIP2Error

# 日志配置
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

# 常量
INPUT_URL = "https://raw.githubusercontent.com/gxiaobang/api/main/CloudflareST_darwin_amd64/nodes.csv"
INPUT_FILE = "input.csv"
IP_LIST_FILE = "ip.txt"
FINAL_CSV = "ip.csv"
IPS_FILE = "ips.txt"
GEOIP_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/main/GeoLite2-Country.mmdb"
GEOIP_DB_PATH = Path("GeoLite2-Country.mmdb")
DESIRED_COUNTRIES = ['TW', 'JP', 'HK', 'SG', 'KR', 'IN', 'KP', 'VN', 'TH', 'MM']
REQUIRED_PACKAGES = ['requests', 'charset_normalizer', 'geoip2']

# 国家映射
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
    'EE': ('🇪🇪', '爱沙尼亚'), 'LV': ('�Lv', '拉脱维亚'), 'LT': ('🇱🇹', '立陶宛')
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
country_cache = {}

def check_dependencies():
    """检查 Python 依赖包"""
    for pkg in REQUIRED_PACKAGES:
        if not importlib.util.find_spec(pkg):
            logger.error(f"缺少依赖包: {pkg}")
            sys.exit(1)

def download_geoip_database(url: str, dest_path: Path) -> bool:
    """下载 GeoIP 数据库"""
    try:
        retries = Retry(total=3, backoff_factor=1)
        adapter = requests.adapters.HTTPAdapter(max_retries=retries)
        session = requests.Session()
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        response = session.get(url, stream=True, timeout=30)
        response.raise_for_status()
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        logger.info(f"GeoIP 数据库下载完成: {dest_path}")
        return True
    except Exception as e:
        logger.error(f"下载 GeoIP 数据库失败: {e}")
        return False

def download_geoip_database_maxmind(dest_path: Path) -> bool:
    """从 MaxMind 下载 GeoIP 数据库（备用）"""
    maxmind_key = os.getenv("MAXMIND_LICENSE_KEY")
    if not maxmind_key:
        logger.warning("未找到 MAXMIND_LICENSE_KEY，跳过 MaxMind 下载")
        return False
    url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={maxmind_key}&suffix=tar.gz"
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            for chunk in response.iter_content(chunk_size=8192):
                tmp.write(chunk)
            tmp_path = tmp.name
        import tarfile
        with tarfile.open(tmp_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("GeoLite2-Country.mmdb"):
                    tar.extract(member, dest_path.parent)
                    extracted_path = dest_path.parent / member.name
                    extracted_path.rename(dest_path)
                    break
        os.unlink(tmp_path)
        logger.info(f"MaxMind GeoIP 数据库下载完成: {dest_path}")
        return True
    except Exception as e:
        logger.error(f"MaxMind 下载失败: {e}")
        return False

def init_geoip_reader():
    """初始化 GeoIP 数据库"""
    global geoip_reader
    if not GEOIP_DB_PATH.exists():
        logger.info("GeoIP 数据库不存在，尝试下载")
        if not download_geoip_database(GEOIP_DB_URL, GEOIP_DB_PATH):
            logger.warning("主下载源失败，尝试 MaxMind")
            if not download_geoip_database_maxmind(GEOIP_DB_PATH):
                logger.error("无法下载 GeoIP 数据库")
                sys.exit(1)
    try:
        geoip_reader = Reader(GEOIP_DB_PATH)
        logger.info("GeoIP 数据库初始化完成")
    except Exception as e:
        logger.error(f"初始化 GeoIP 数据库失败: {e}")
        sys.exit(1)

def close_geoip_reader():
    """关闭 GeoIP 数据库"""
    global geoip_reader
    if geoip_reader:
        geoip_reader.close()
        geoip_reader = None
        logger.info("GeoIP 数据库已关闭")

def get_country_from_ip(ip: str, cache: Dict[str, str]) -> str:
    """根据 IP 获取国家代码"""
    if ip in cache:
        return cache[ip]
    if not geoip_reader:
        logger.error("GeoIP 数据库未初始化")
        return ""
    try:
        response = geoip_reader.country(ip)
        country_code = response.country.iso_code or ""
        cache[ip] = country_code
        return country_code
    except GeoIP2Error:
        cache[ip] = ""
        return ""

def normalize_country(country: str) -> str:
    """标准化国家名称到 ISO 代码"""
    if not country:
        return ""
    country = country.strip().upper()
    if country in COUNTRY_LABELS:
        return country
    for alias, code in COUNTRY_ALIASES.items():
        if country == alias.upper():
            return code
    return ""

def fetch_and_save_to_temp_file(url: str) -> Optional[str]:
    """下载 URL 数据到临时文件"""
    try:
        retries = Retry(total=10, backoff_factor=2)
        adapter = requests.adapters.HTTPAdapter(max_retries=retries)
        session = requests.Session()
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        response = session.get(url, timeout=30)
        response.raise_for_status()
        response.encoding = response.apparent_encoding
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".csv", delete=False) as f:
            f.write(response.text)
            return f.name
    except Exception as e:
        logger.error(f"下载 URL 失败: {e}")
        return None

def cleanup_temp_file(temp_file: str):
    """清理临时文件"""
    if temp_file and os.path.exists(temp_file):
        try:
            os.unlink(temp_file)
            logger.debug(f"已删除临时文件: {temp_file}")
        except Exception as e:
            logger.warning(f"删除临时文件失败: {e}")

def extract_ip_ports_from_content(content: str) -> List[Tuple[str, int, str]]:
    """解析任意格式的节点数据"""
    ip_ports = []
    try:
        # 尝试 JSON 格式
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    ip = item.get("ip") or item.get("host") or item.get("address")
                    port = item.get("port")
                    country = item.get("country", "")
                    if ip and port:
                        try:
                            port = int(port)
                            country = normalize_country(country)
                            ip_ports.append((ip, port, country))
                        except (ValueError, TypeError):
                            continue
            logger.debug("解析为 JSON 格式")
            return ip_ports
        except json.JSONDecodeError:
            pass

        # 尝试 CSV 或类 CSV 格式
        lines = content.splitlines()
        separators = [",", ";", "\t", "|"]
        for sep in separators:
            if any(sep in line for line in lines[:5]):
                reader = csv.reader(lines, delimiter=sep, skipinitialspace=True)
                for row in reader:
                    if len(row) >= 2:
                        ip = row[0].strip()
                        try:
                            port = int(row[1].strip())
                            country = normalize_country(row[2]) if len(row) > 2 else ""
                            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                                ip_ports.append((ip, port, country))
                        except (ValueError, IndexError):
                            continue
                if ip_ports:
                    logger.debug(f"解析为 CSV 格式，分隔符: {sep}")
                    return ip_ports

        # 尝试纯文本
        ip_port_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::|\s+)(\d+)")
        for line in lines:
            match = ip_port_pattern.search(line)
            if match:
                ip, port = match.groups()
                try:
                    port = int(port)
                    ip_ports.append((ip, port, ""))
                except ValueError:
                    continue
        if ip_ports:
            logger.debug("解析为纯文本格式")
            return ip_ports

        logger.warning("无法解析数据格式")
        return []
    except Exception as e:
        logger.error(f"解析数据失败: {e}")
        return []

def extract_ip_ports_from_file(file_path: str) -> List[Tuple[str, int, str]]:
    """从文件中提取节点"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return extract_ip_ports_from_content(content)
    except Exception as e:
        logger.error(f"读取文件 {file_path} 失败: {e}")
        return []

def write_ip_list(ip_ports: List[Tuple[str, int, str]]) -> Optional[str]:
    """筛选并写入 ip.txt"""
    start_time = time.time()
    filtered_ip_ports = set()
    country_counts = Counter()
    filtered_counts = Counter()

    logger.info(f"开始处理 {len(ip_ports)} 个节点...")
    init_geoip_reader()

    for ip, port, country in ip_ports:
        try:
            if not country:
                country = get_country_from_ip(ip, country_cache)
            if country in DESIRED_COUNTRIES:
                filtered_ip_ports.add((ip, port))
                country_counts[country] += 1
            else:
                filtered_counts[country] += 1
        except Exception as e:
            logger.warning(f"处理节点 {ip}:{port} 失败: {e}")
            continue

    total_retained = len(filtered_ip_ports)
    total_filtered = len(ip_ports) - total_retained
    logger.info(f"筛选结果：保留 {total_retained} 个节点，过滤 {total_filtered} 个节点")
    logger.info(f"保留国家分布：{dict(country_counts)}")
    if filtered_counts:
        logger.info(f"过滤国家分布：{dict(filtered_counts)}")

    if not filtered_ip_ports:
        logger.error("未保留任何节点")
        return None

    try:
        with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
            for ip, port in sorted(filtered_ip_ports):
                f.write(f"{ip} {port}\n")
        logger.info(f"生成 {IP_LIST_FILE}，包含 {total_retained} 个节点（耗时：{time.time() - start_time:.2f} 秒）")
        return IP_LIST_FILE
    except Exception as e:
        logger.error(f"写入 {IP_LIST_FILE} 失败: {e}")
        return None

def find_speedtest_script() -> str:
    """查找测速脚本"""
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
    logger.error("未找到测速脚本")
    return ""

SPEEDTEST_SCRIPT = find_speedtest_script()

def run_speed_test() -> Optional[str]:
    """逐行测速，调用 iptest.sh"""
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
    csv_rows = [["IP地址", "端口", "TLS", "数据中心", "地区", "国际代码", "国家", "城市", "网络延迟", "下载速度MB/s"]]
    output_pattern = re.compile(r"发现有效IP (\S+) 端口 (\d+) 位置信息 (\S+) 延迟 (\d+) 毫秒")
    location_to_country = {
        "福冈": "JP", "东京": "JP", "大阪": "JP",
        "首尔": "KR", "釜山": "KR",
        "新加坡": "SG",
        "香港": "HK",
        "台北": "TW", "高雄": "TW",
        # 可扩展其他城市
    }

    for line in ip_lines:
        try:
            ip, port = line.split()
        except ValueError:
            logger.warning(f"无效行: {line}")
            continue

        logger.info(f"测试节点: {ip}:{port}")
        try:
            process = subprocess.Popen(
                [SPEEDTEST_SCRIPT, ip, port],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1
            )
            stdout_lines, stderr_lines = [], []
            def read_stream(stream, lines):
                while True:
                    line = stream.readline()
                    if not line:
                        break
                    lines.append(line)
                    logger.info(line.strip())
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
                logger.debug(f"节点 {ip}:{port} 输出: {stdout}")
            if stderr:
                logger.warning(f"节点 {ip}:{port} 错误: {stderr}")

            if return_code != 0:
                logger.warning(f"节点 {ip}:{port} 测速失败，返回码: {return_code}")
                continue

            # 解析 iptest 输出
            match = output_pattern.search(stdout)
            if match:
                ip_out, port_out, location, latency = match.groups()
                country = location_to_country.get(location, "")
                if not country:
                    country = get_country_from_ip(ip, country_cache)
                _, country_name = COUNTRY_LABELS.get(country, ('', location))
                csv_rows.append([
                    ip, port, "", "", "", country, country_name, location,
                    f"{latency} ms", "0.00"  # 下载速度未知
                ])
            else:
                logger.warning(f"节点 {ip}:{port} 输出格式不匹配")
                continue
        except Exception as e:
            logger.error(f"测试节点 {ip}:{port} 异常: {e}")
            continue

    if len(csv_rows) <= 1:
        logger.error("未生成有效测速结果")
        return None

    try:
        with open(FINAL_CSV, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerows(csv_rows)
        logger.info(f"{FINAL_CSV} 已生成，节点数：{len(csv_rows) - 1}")
        logger.info(f"测速完成，耗时: {time.time() - start_time:.2f} 秒")
        return FINAL_CSV
    except Exception as e:
        logger.error(f"写入 {FINAL_CSV} 失败: {e}")
        return None

def filter_speed_and_deduplicate(csv_file: str):
    """按延迟排序并去重"""
    try:
        nodes = []
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            for row in reader:
                try:
                    if len(row) >= 9:
                        ip, port, _, _, _, country, _, _, latency = row[:9]
                        latency = float(latency.replace("ms", "").strip())
                        nodes.append((ip, int(port), country, latency, row))
                except (ValueError, IndexError):
                    continue
        nodes.sort(key=lambda x: x[3])  # 按延迟升序
        unique_nodes = []
        seen = set()
        for node in nodes:
            ip_port = f"{node[0]}:{node[1]}"
            if ip_port not in seen:
                seen.add(ip_port)
                unique_nodes.append(node[4])
        with open(csv_file, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(unique_nodes)
        logger.info(f"已排序并去重，保留 {len(unique_nodes)} 个节点")
    except Exception as e:
        logger.error(f"处理 {csv_file} 失败: {e}")

def generate_ips_file(csv_file: str):
    """生成 ips.txt"""
    start_time = time.time()
    final_nodes = []
    country_counts = Counter()
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            for row in reader:
                try:
                    if len(row) >= 6:
                        ip, port, _, _, _, country = row[:6]
                        country = country.strip().upper()
                        if not DESIRED_COUNTRIES or country in DESIRED_COUNTRIES:
                            final_nodes.append((ip, int(port), country))
                            country_counts[country] += 1
                except (ValueError, IndexError):
                    continue
    except Exception as e:
        logger.error(f"读取 {csv_file} 失败: {e}")
        return

    if not final_nodes:
        logger.error(f"未生成 {IPS_FILE}")
        return

    try:
        with open(IPS_FILE, "w", encoding="utf-8") as f:
            for idx, (ip, port, country) in enumerate(sorted(final_nodes, key=lambda x: x[2]), 1):
                flag, name = COUNTRY_LABELS.get(country, ('🌐', '未知'))
                f.write(f"{ip}:{port}#{flag}{name}-{idx}\n")
        logger.info(f"{IPS_FILE} 已生成，节点数：{len(final_nodes)} (耗时: {time.time() - start_time:.2f} 秒)")
        logger.info(f"国家分布：{dict(country_counts)}")
    except Exception as e:
        logger.error(f"写入 {IPS_FILE} 失败: {e}")

def main():
    start_time = time.time()
    logger.info("脚本开始")
    check_dependencies()
    parser = argparse.ArgumentParser(description="IP Filter and Speed Test")
    parser.add_argument("--generate-ips", action="store_true")
    args = parser.parse_args()
    try:
        if not args.generate_ips:
            ip_ports = []
            if os.path.exists(INPUT_FILE):
                logger.info(f"从 {INPUT_FILE} 获取节点")
                ip_ports = extract_ip_ports_from_file(INPUT_FILE)
            else:
                logger.info(f"未找到 {INPUT_FILE}，从 URL {INPUT_URL} 下载")
                temp_file = fetch_and_save_to_temp_file(INPUT_URL)
                if temp_file:
                    try:
                        ip_ports = extract_ip_ports_from_file(temp_file)
                    finally:
                        cleanup_temp_file(temp_file)
            if not ip_ports:
                logger.error("未获取到有效节点")
                sys.exit(1)
            ip_list_file = write_ip_list(ip_ports)
            if not ip_list_file:
                sys.exit(1)
        else:
            csv_file = run_speed_test()
            if not csv_file:
                sys.exit(1)
            filter_speed_and_deduplicate(csv_file)
            generate_ips_file(csv_file)
        logger.info(f"脚本完成 (总耗时: {time.time() - start_time:.2f} 秒)")
    except Exception as e:
        logger.error(f"脚本异常: {e}")
        sys.exit(1)
    finally:
        close_geoip_reader()

if __name__ == "__main__":
    main()
