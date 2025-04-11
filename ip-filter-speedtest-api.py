import requests
import re
import csv
import subprocess
import os
import logging
import sys
import threading
import time
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

def fetch_and_extract_ip_ports_from_url(url: str) -> List[Tuple[str, int]]:
    """从 URL 获取并提取 IPv4 和 IPv6 地址及端口，去重"""
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
        logger.error(f"获取内容失败: {e}")
        return []

    from charset_normalizer import detect
    result = detect(raw_content)
    encoding = result.get("encoding", "utf-8")
    logger.info(f"检测到 URL 内容的编码: {encoding}")

    try:
        content = raw_content.decode(encoding)
    except UnicodeDecodeError as e:
        logger.error(f"无法以 {encoding} 解码 URL 内容: {e}")
        return []

    content = content.replace('\r\n', '\n').replace('\r', '\n')
    lines = content.splitlines()

    ip_port_pattern = re.compile(r'(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]|(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))[ :,\t](\d{1,5})')

    comma_count = sum(1 for line in lines[:5] if ',' in line and line.strip())
    semicolon_count = sum(1 for line in lines[:5] if ';' in line and line.strip())
    tab_count = sum(1 for line in lines[:5] if '\t' in line and line.strip())
    space_count = sum(1 for line in lines[:5] if ' ' in line and line.strip())

    delimiter = None
    if comma_count > max(semicolon_count, tab_count, space_count) and comma_count > 0:
        delimiter = ','
    elif semicolon_count > max(comma_count, tab_count, space_count) and semicolon_count > 0:
        delimiter = ';'
    elif tab_count > max(comma_count, semicolon_count, space_count) and tab_count > 0:
        delimiter = '\t'
    elif space_count > max(comma_count, semicolon_count, tab_count) and space_count > 0:
        delimiter = ' '
    logger.info(f"检测到的分隔符: {delimiter if delimiter else '未检测到，使用正则匹配'}")

    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        match = ip_port_pattern.match(line)
        if match:
            server = match.group(1).strip('[]')
            port = int(match.group(4))
            if 0 <= port <= 65535:
                server_port_pairs.append((server, port))
                logger.debug(f"从正则解析到: {server}:{port}")
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid port range)")
            continue

        if delimiter:
            fields = line.split(delimiter)
            if len(fields) >= 2:
                server = fields[0].strip('[]')
                try:
                    port = int(fields[1].strip())
                    if 0 <= port <= 65535 and (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', server) or re.match(r'^(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$', server)):
                        server_port_pairs.append((server, port))
                        logger.debug(f"从分隔符解析到: {server}:{port}")
                    else:
                        invalid_lines.append(f"Line {i}: {line} (Invalid port range or IP format)")
                except (ValueError, TypeError):
                    invalid_lines.append(f"Line {i}: {line} (Invalid port format)")
            else:
                invalid_lines.append(f"Line {i}: {line} (Too few fields)")
        else:
            invalid_lines.append(f"Line {i}: {line} (No valid format detected)")

    unique_server_port_pairs = list(dict.fromkeys(server_port_pairs))
    logger.info(f"去重后共 {len(unique_server_port_pairs)} 个 server:port 对")

    if invalid_lines:
        logger.info(f"发现 {len(invalid_lines)} 个无效条目: {invalid_lines[:5]}")

    return unique_server_port_pairs

def extract_ip_ports_from_file(file_path: str) -> List[Tuple[str, int]]:
    """从本地文件提取 IPv4 和 IPv6 地址及端口，支持任意格式，去重"""
    server_port_pairs = []
    invalid_lines = []

    if not os.path.exists(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []

    with open(file_path, "rb") as f:
        raw_data = f.read()
    from charset_normalizer import detect
    result = detect(raw_data)
    encoding = result.get("encoding", "utf-8")
    logger.info(f"检测到文件 {file_path} 的编码: {encoding}")

    try:
        content = raw_data.decode(encoding)
    except UnicodeDecodeError as e:
        logger.error(f"无法以 {encoding} 解码文件 {file_path}: {e}")
        return []

    logger.info(f"从本地文件 {file_path} 读取内容 (长度: {len(content)} 字节)")

    content = content.replace('\r\n', '\n').replace('\r', '\n')
    lines = content.splitlines()

    ip_port_pattern = re.compile(r'(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]|(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))[ :,\t](\d{1,5})')

    comma_count = sum(1 for line in lines[:5] if ',' in line and line.strip())
    semicolon_count = sum(1 for line in lines[:5] if ';' in line and line.strip())
    tab_count = sum(1 for line in lines[:5] if '\t' in line and line.strip())
    space_count = sum(1 for line in lines[:5] if ' ' in line and line.strip())

    delimiter = None
    if comma_count > max(semicolon_count, tab_count, space_count) and comma_count > 0:
        delimiter = ','
    elif semicolon_count > max(comma_count, tab_count, space_count) and semicolon_count > 0:
        delimiter = ';'
    elif tab_count > max(comma_count, semicolon_count, space_count) and tab_count > 0:
        delimiter = '\t'
    elif space_count > max(comma_count, semicolon_count, tab_count) and space_count > 0:
        delimiter = ' '
    logger.info(f"检测到的分隔符: {delimiter if delimiter else '未检测到，使用正则匹配'}")

    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        match = ip_port_pattern.match(line)
        if match:
            server = match.group(1).strip('[]')
            port = int(match.group(4))
            if 0 <= port <= 65535:
                server_port_pairs.append((server, port))
                logger.debug(f"从正则解析到: {server}:{port}")
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid port range)")
            continue

        if delimiter:
            fields = line.split(delimiter)
            if len(fields) >= 2:
                server = fields[0].strip('[]')
                try:
                    port = int(fields[1].strip())
                    if 0 <= port <= 65535 and (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', server) or re.match(r'^(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$', server)):
                        server_port_pairs.append((server, port))
                        logger.debug(f"从分隔符解析到: {server}:{port}")
                    else:
                        invalid_lines.append(f"Line {i}: {line} (Invalid port range or IP format)")
                except (ValueError, TypeError):
                    invalid_lines.append(f"Line {i}: {line} (Invalid port format)")
            else:
                invalid_lines.append(f"Line {i}: {line} (Too few fields)")
        else:
            invalid_lines.append(f"Line {i}: {line} (No valid format detected)")

    unique_server_port_pairs = list(dict.fromkeys(server_port_pairs))
    logger.info(f"去重后共 {len(unique_server_port_pairs)} 个 server:port 对")

    if invalid_lines:
        logger.info(f"发现 {len(invalid_lines)} 个无效条目: {invalid_lines[:5]}")

    return unique_server_port_pairs

def write_ip_list(ip_ports: List[Tuple[str, int]]) -> str:
    """写入 ip.txt，格式为 'ip port'"""
    if not ip_ports:
        logger.error(f"无有效节点，无法生成 {IP_LIST_FILE}")
        return None
    with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
        for ip, port in ip_ports:
            f.write(f"{ip} {port}\n")
    logger.info(f"生成 {IP_LIST_FILE}，包含 {len(ip_ports)} 个节点")
    return IP_LIST_FILE

def run_speed_test() -> str:
    try:
        cmd = [SPEEDTEST_SCRIPT]
        logger.info(f"运行测速命令: {' '.join(cmd)}")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,
            encoding='utf-8',
            errors='replace'
        )

        stdout_lines = []
        stderr_lines = []

        total_ips = 0
        with open(IP_LIST_FILE, 'r') as f:
            total_ips = len(f.readlines())

        completed_ips = 0

        def read_stream(stream, lines, stream_name):
            nonlocal completed_ips
            while True:
                line = stream.readline()
                if not line:
                    break
                if stream_name == "stdout":
                    print(line.strip())
                    # 假设每行输出表示一个 IP 的测速结果
                    if line.strip() and not line.startswith("Progress:"):  # 排除非结果行
                        completed_ips += 1
                        print(f"\r测速进度: 已完成 {completed_ips}/{total_ips} ({completed_ips/total_ips*100:.2f}%)", end='')
                lines.append(line)

        stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, stdout_lines, "stdout"))
        stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, stderr_lines, "stderr"))
        stdout_thread.start()
        stderr_thread.start()

        stdout_thread.join()
        stderr_thread.join()

        return_code = process.wait()

        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)
        if stderr:
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
    """去重 ip.csv 中的节点"""
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在，跳过去重")
        return
    seen = set()
    final_rows = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            if len(row) < 2:
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

def get_country_from_ip(ip: str, cache: dict) -> str:
    """通过 IP 查询国家代码，带缓存和重试"""
    if ip in cache:
        return cache[ip]
    for attempt in range(3):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            response.raise_for_status()
            data = response.json()
            country_code = data.get('countryCode', '')
            if country_code:
                cache[ip] = country_code
                logger.debug(f"IP {ip} 国家代码: {country_code}")
                return country_code
            else:
                logger.warning(f"IP {ip} 无国家代码")
                return ''
        except Exception as e:
            logger.error(f"查询 IP {ip} 国家失败 (尝试 {attempt + 1}/3): {e}")
            if attempt == 2:
                return ''
            time.sleep(2)
    return ''

def generate_ips_file(csv_file: str):
    """读取 ip.csv，查询国家并写入 ips.txt，仅保留指定国家"""
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在，跳过生成 {IPS_FILE}")
        return

    country_cache = {}
    final_nodes = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if len(row) < 2:
                continue
            ip, port = row[0], row[1]
            if not (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) or re.match(r'^(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$', ip)) or not (0 <= int(port) <= 65535):
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

    with open(IPS_FILE, "w", encoding="utf-8") as f:
        for ip, port, label in labeled_nodes:
            f.write(f"{ip}:{port}#{label}\n")
    logger.info(f"生成 {IPS_FILE}，包含 {len(labeled_nodes)} 个节点")

def main(prefer_url: bool = False):
    """主函数"""
    if not prefer_url and os.path.exists(INPUT_FILE):
        ip_ports = extract_ip_ports_from_file(INPUT_FILE)
        if not ip_ports:
            logger.error("未找到符合条件的节点")
            sys.exit(1)
        ip_file = write_ip_list(ip_ports)
        if ip_file:
            with open(ip_file, "r", encoding="utf-8") as f:
                logger.info(f"ip.txt 内容:\n{f.read()}")
    else:
        ip_ports = fetch_and_extract_ip_ports_from_url(URL)
        if not ip_ports:
            logger.error("未找到符合条件的节点")
            sys.exit(1)
        ip_file = write_ip_list(ip_ports)
        if ip_file:
            with open(ip_file, "r", encoding="utf-8") as f:
                logger.info(f"ip.txt 内容:\n{f.read()}")

    csv_file = run_speed_test()
    if csv_file:
        filter_speed_and_deduplicate(csv_file)
        if os.path.exists(csv_file):
            generate_ips_file(csv_file)
        else:
            logger.info("无符合条件的节点，跳过生成 ips.txt")
    else:
        logger.info("无测速结果")

if __name__ == "__main__":
    prefer_url = '--url-first' in sys.argv
    logger.info(f"数据源优先级: {'URL 优先' if prefer_url else '本地文件优先'}")
    logger.info(f"筛选国家: {DESIRED_COUNTRIES}")
    main(prefer_url=prefer_url)