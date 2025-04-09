import requests
import re
import csv
import subprocess
import os
import logging
from io import StringIO
from typing import List, Tuple
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# 配置
URL = "https://bihai.cf/CFIP/CUCC/standard.csv"  # 如果有 URL，替换为实际地址；否则需手动提供 CSV 内容
IP_LIST_FILE = "ip.txt"
SPEEDTEST_SCRIPT = "./iptest.sh"  # 调用 iptest.sh 脚本
FINAL_CSV = "ip.csv"  # iptest.sh 默认输出文件
MIN_SPEED_MBPS = 0.1  # 最低速度 0.1 MB/s，手动过滤
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com/"
}

# 亚太区国家代码（不包括 AU 和 NZ）
ASIA_PACIFIC_REGIONS = {
    'JP', 'KR', 'SG', 'TW', 'HK', 'MY', 'TH', 'ID', 'PH',
    'VN', 'IN', 'MO', 'BN', 'KH', 'LA', 'MM', 'TL'
}
COUNTRY_MAPPING = {
    '台湾': 'TW', '日本': 'JP', '韩国': 'KR', '新加坡': 'SG', '香港': 'HK',
    '马来西亚': 'MY', '泰国': 'TH', '印度尼西亚': 'ID', '菲律宾': 'PH',
    '越南': 'VN', '印度': 'IN', '澳门': 'MO', '文莱': 'BN',
    '柬埔寨': 'KH', '老挝': 'LA', '缅甸': 'MM', '东帝汶': 'TL',
    '美国': 'US'
}

def fetch_content(url: str) -> str:
    """从 URL 下载内容"""
    try:
        logger.info(f"正在从 {url} 获取数据...")
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, headers=HEADERS, timeout=30)
        response.raise_for_status()
        logger.info("成功获取CSV数据")
        return response.text
    except requests.RequestException as e:
        logger.error(f"获取CSV数据失败: {e}")
        return None

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

def is_delay(s: str) -> bool:
    """验证延迟值"""
    return bool(re.match(r"^\d+(\.\d+)?\s*ms$", s)) or s.isdigit()

def extract_ip_ports(content: str) -> List[Tuple[str, str, str]]:
    """提取 IP、端口和国家代码，只保留亚太区节点"""
    try:
        f = StringIO(content)
        delimiters = [',', '\t', ';']
        for delimiter in delimiters:
            f.seek(0)
            reader = csv.reader(f, delimiter=delimiter)
            rows = list(reader)
            if len(rows) > 1 and len(rows[0]) > 1:
                break
        else:
            logger.error("无法确定CSV分隔符")
            return []

        header = rows[0]
        data_rows = rows[1:]
        logger.info(f"CSV字段数: {len(header)}, 示例行: {data_rows[0] if data_rows else '无数据'}")

        # 字段位置（根据 CSV 结构调整）
        ip_col = 0      # IP 地址
        port_col = 1    # 端口
        country_col = 5 # 国家代码 (TW, JP 等)
        delay_col = 8   # 延迟

        logger.info(f"最终字段位置 - IP: {ip_col}, Port: {port_col}, Country: {country_col}, Delay: {delay_col}")

        ip_ports = []
        for row in data_rows:
            if len(row) <= max(ip_col, port_col, country_col, delay_col or -1):
                continue
            try:
                ip = row[ip_col].strip()
                if not is_ip(ip):
                    logger.debug(f"无效 IP: {ip}")
                    continue

                port = row[port_col].strip()
                if not is_port(port):
                    port = "443"  # 默认使用 443 端口（HTTPS）
                port = str(int(port))

                country_raw = row[country_col].strip()
                country = COUNTRY_MAPPING.get(country_raw, country_raw.upper())
                if country not in ASIA_PACIFIC_REGIONS:
                    continue

                delay = 9999
                if delay_col is not None and row[delay_col].strip():
                    delay_str = row[delay_col].strip()
                    if is_delay(delay_str):
                        delay = float(delay_str.replace(' ms', '')) if 'ms' in delay_str else float(delay_str)

                ip_ports.append((delay, ip, port, country))

            except (ValueError, IndexError) as e:
                logger.debug(f"跳过无效行: {row} - {e}")
                continue

        # 按延迟排序
        ip_ports.sort(key=lambda x: x[0])
        logger.info(f"提取到 {len(ip_ports)} 个亚太区节点")
        return [(ip, port, country) for _, ip, port, country in ip_ports]

    except Exception as e:
        logger.error(f"解析CSV失败: {e}")
        return []

def write_ip_list(ip_ports: List[Tuple[str, str, str]]) -> str:
    """写入 ip.txt"""
    with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
        for ip, port, _ in ip_ports:
            f.write(f"{ip} {port}\n")
    logger.info(f"生成 {IP_LIST_FILE}，包含 {len(ip_ports)} 个节点")
    return IP_LIST_FILE

def run_speed_test() -> str:
    """运行测速，调用 iptest.sh"""
 import requests
import re
import csv
import subprocess
import os
import logging
from io import StringIO
from typing import List, Tuple
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# 配置
URL = "https://bihai.cf/CFIP/CUCC/standard.csv"  # 如果有 URL，替换为实际地址；否则需手动提供 CSV 内容
IP_LIST_FILE = "ip.txt"
SPEEDTEST_SCRIPT = "./iptest.sh"  # 调用 iptest.sh 脚本
FINAL_CSV = "ip.csv"  # iptest.sh 默认输出文件
MIN_SPEED_MBPS = 0.1  # 最低速度 0.1 MB/s，手动过滤
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com/"
}

# 亚太区国家代码（不包括 AU 和 NZ）
ASIA_PACIFIC_REGIONS = {
    'JP', 'KR', 'SG', 'TW', 'HK', 'MY', 'TH', 'ID', 'PH',
    'VN', 'IN', 'MO', 'BN', 'KH', 'LA', 'MM', 'TL'
}
COUNTRY_MAPPING = {
    '台湾': 'TW', '日本': 'JP', '韩国': 'KR', '新加坡': 'SG', '香港': 'HK',
    '马来西亚': 'MY', '泰国': 'TH', '印度尼西亚': 'ID', '菲律宾': 'PH',
    '越南': 'VN', '印度': 'IN', '澳门': 'MO', '文莱': 'BN',
    '柬埔寨': 'KH', '老挝': 'LA', '缅甸': 'MM', '东帝汶': 'TL',
    '美国': 'US'
}

def fetch_content(url: str) -> str:
    """从 URL 下载内容"""
    try:
        logger.info(f"正在从 {url} 获取数据...")
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get(url, headers=HEADERS, timeout=30)
        response.raise_for_status()
        logger.info("成功获取CSV数据")
        return response.text
    except requests.RequestException as e:
        logger.error(f"获取CSV数据失败: {e}")
        return None

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

def is_delay(s: str) -> bool:
    """验证延迟值"""
    return bool(re.match(r"^\d+(\.\d+)?\s*ms$", s)) or s.isdigit()

def extract_ip_ports(content: str) -> List[Tuple[str, str, str]]:
    """提取 IP、端口和国家代码，只保留亚太区节点"""
    try:
        f = StringIO(content)
        delimiters = [',', '\t', ';']
        for delimiter in delimiters:
            f.seek(0)
            reader = csv.reader(f, delimiter=delimiter)
            rows = list(reader)
            if len(rows) > 1 and len(rows[0]) > 1:
                break
        else:
            logger.error("无法确定CSV分隔符")
            return []

        header = rows[0]
        data_rows = rows[1:]
        logger.info(f"CSV字段数: {len(header)}, 示例行: {data_rows[0] if data_rows else '无数据'}")

        # 字段位置（根据 CSV 结构调整）
        ip_col = 0      # IP 地址
        port_col = 1    # 端口
        country_col = 5 # 国家代码 (TW, JP 等)
        delay_col = 8   # 延迟

        logger.info(f"最终字段位置 - IP: {ip_col}, Port: {port_col}, Country: {country_col}, Delay: {delay_col}")

        ip_ports = []
        for row in data_rows:
            if len(row) <= max(ip_col, port_col, country_col, delay_col or -1):
                continue
            try:
                ip = row[ip_col].strip()
                if not is_ip(ip):
                    logger.debug(f"无效 IP: {ip}")
                    continue

                port = row[port_col].strip()
                if not is_port(port):
                    port = "443"  # 默认使用 443 端口（HTTPS）
                port = str(int(port))

                country_raw = row[country_col].strip()
                country = COUNTRY_MAPPING.get(country_raw, country_raw.upper())
                if country not in ASIA_PACIFIC_REGIONS:
                    continue

                delay = 9999
                if delay_col is not None and row[delay_col].strip():
                    delay_str = row[delay_col].strip()
                    if is_delay(delay_str):
                        delay = float(delay_str.replace(' ms', '')) if 'ms' in delay_str else float(delay_str)

                ip_ports.append((delay, ip, port, country))

            except (ValueError, IndexError) as e:
                logger.debug(f"跳过无效行: {row} - {e}")
                continue

        # 按延迟排序
        ip_ports.sort(key=lambda x: x[0])
        logger.info(f"提取到 {len(ip_ports)} 个亚太区节点")
        return [(ip, port, country) for _, ip, port, country in ip_ports]

    except Exception as e:
        logger.error(f"解析CSV失败: {e}")
        return []

def write_ip_list(ip_ports: List[Tuple[str, str, str]]) -> str:
    """写入 ip.txt"""
    with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
        for ip, port, _ in ip_ports:
            f.write(f"{ip} {port}\n")
    logger.info(f"生成 {IP_LIST_FILE}，包含 {len(ip_ports)} 个节点")
    return IP_LIST_FILE

def run_speed_test() -> str:
    """运行测速，调用 iptest.sh"""
    try:
        cmd = [SPEEDTEST_SCRIPT]  # 直接调用 ./iptest.sh
        logger.info(f"运行测速命令: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        logger.info(f"iptest.sh stdout: {result.stdout}")
        logger.info(f"iptest.sh stderr: {result.stderr}")
        if result.returncode == 0:
            if os.path.exists(FINAL_CSV):
                logger.info(f"测速完成，结果保存到 {FINAL_CSV}")
                return FINAL_CSV
            else:
                logger.info(f"测速完成，但 {FINAL_CSV} 未生成，可能是没有符合条件的节点")
                return None
        else:
            logger.error(f"测速失败: {result.stderr}")
            return None
    except Exception as e:
        logger.error(f"运行测速失败: {e}")
        return None

def filter_speed_and_deduplicate(csv_file: str, min_speed: float):
    """过滤速度低于 min_speed 的节点并去重"""
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在，跳过过滤和去重")
        return
    seen = set()
    final_rows = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        speed_idx = 2  # 假设速度在第 3 列（根据 iptest 输出格式调整）
        for row in reader:
            if len(row) <= speed_idx:
                continue
            try:
                speed = float(row[speed_idx])  # 速度单位 MB/s
                if speed < min_speed:
                    continue
            except (ValueError, IndexError):
                continue
            key = (row[0], row[1])  # 以 IP 和 Port 去重
            if key not in seen:
                seen.add(key)
                final_rows.append(row)

    if not final_rows:
        logger.info(f"没有节点的速度高于 {min_speed} MB/s，删除 {csv_file}")
        os.remove(csv_file)
        return

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(final_rows)
    logger.info(f"过滤和去重完成，{csv_file} 包含 {len(final_rows)} 条记录")

def main():
    # 如果有 URL，直接抓取；否则需手动提供 CSV 内容
    content = fetch_content(URL)
    if not content:
        try:
            with open("input.csv", "r", encoding="utf-8") as f:
                content = f.read()
            logger.info("从本地 input.csv 读取内容")
        except FileNotFoundError:
            logger.error("无 URL 且本地 input.csv 不存在，程序退出")
            exit(1)

    # 提取亚太区节点
    ip_ports = extract_ip_ports(content)
    if not ip_ports:
        logger.error("未找到符合条件的亚太区节点")
        exit(1)

    # 写入 ip.txt
    ip_file = write_ip_list(ip_ports)

    # 打印 ip.txt 内容
    with open(ip_file, "r", encoding="utf-8") as f:
        logger.info(f"ip.txt 内容:\n{f.read()}")

    # 运行测速
    csv_file = run_speed_test()
    if csv_file:
        # 过滤速度并去重
        filter_speed_and_deduplicate(csv_file, MIN_SPEED_MBPS)
        if not os.path.exists(csv_file):
            logger.info("无符合速度条件的节点")
    else:
        logger.info("无测速结果")

if __name__ == "__main__":
    main()
