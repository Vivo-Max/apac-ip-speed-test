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

def extract_ip_ports_from_file(file_path: str) -> List[Tuple[str, int]]:
    """从本地文件提取 IPv4 和 IPv6 地址及端口，支持任意格式，去重"""
    server_port_pairs = []
    invalid_lines = []

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
    lines = content.splitlines()

    logger.info(f"{file_path} 总行数: {len(lines)}")
    logger.info(f"{file_path} 前 5 行内容: {lines[:5]}")

    # 正则表达式匹配 IPv4 和 IPv6，支持多种分隔符
    ip_port_pattern = re.compile(r'(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]|(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))[: ,;\t](\d{1,5})')

    # 动态检测分隔符
    comma_count = sum(1 for line in lines[:5] if ',' in line and line.strip())
    semicolon_count = sum(1 for line in lines[:5] if ';' in line and line.strip())
    tab_count = sum(1 for line in lines[:5] if '\t' in line and line.strip())
    space_count = sum(1 for line in lines[:5] if ' ' in line and line.strip())
    colon_count = sum(1 for line in lines[:5] if ':' in line and line.strip())

    delimiter = None
    if comma_count > max(semicolon_count, tab_count, space_count, colon_count) and comma_count > 0:
        delimiter = ','
    elif semicolon_count > max(comma_count, tab_count, space_count, colon_count) and semicolon_count > 0:
        delimiter = ';'
    elif tab_count > max(comma_count, semicolon_count, space_count, colon_count) and tab_count > 0:
        delimiter = '\t'
    elif space_count > max(comma_count, semicolon_count, tab_count, colon_count) and space_count > 0:
        delimiter = ' '
    elif colon_count > max(comma_count, semicolon_count, tab_count, space_count) and colon_count > 0:
        delimiter = ':'
    logger.info(f"检测到的分隔符: {delimiter if delimiter else '未检测到，使用正则匹配'}")

    # 解析每一行
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # 使用正则表达式匹配 IP:Port
        match = ip_port_pattern.match(line)
        if match:
            server = match.group(1).strip('[]')  # 去除 IPv6 的方括号
            port = int(match.group(4))
            if 0 <= port <= 65535:
                server_port_pairs.append((server, port))
                logger.debug(f"从正则解析到: {server}:{port}")
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid port range)")
            continue

        # 如果正则未匹配，尝试分隔符解析
        if delimiter:
            fields = line.split(delimiter)
            if len(fields) >= 2:
                server = fields[0].strip('[]')  # 去除可能的方括号
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

    # 去重
    unique_server_port_pairs = list(dict.fromkeys(server_port_pairs))
    logger.info(f"去重后共 {len(unique_server_port_pairs)} 个 server:port 对")
    logger.info(f"解析出的前 5 个 server:port 对: {unique_server_port_pairs[:5]}")

    if invalid_lines:
        logger.info(f"发现 {len(invalid_lines)} 个无效条目: {invalid_lines[:5]}")

    return unique_server_port_pairs

def fetch_and_extract_ip_ports_from_url(url: str) -> List[Tuple[str, int]]:
    """从 URL 获取并提取 IPv4 和 IPv6 地址及端口，去重"""
    server_port_pairs = []
    invalid_lines = []

    # 下载内容
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
    lines = content.splitlines()

    logger.info(f"URL 内容总行数: {len(lines)}")
    logger.info(f"URL 内容前 5 行: {lines[:5]}")

    # 正则表达式匹配 IPv4 和 IPv6
    ip_port_pattern = re.compile(r'(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]|(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))[: ,;\t](\d{1,5})')

    # 动态检测分隔符
    comma_count = sum(1 for line in lines[:5] if ',' in line and line.strip())
    semicolon_count = sum(1 for line in lines[:5] if ';' in line and line.strip())
    tab_count = sum(1 for line in lines[:5] if '\t' in line and line.strip())
    space_count = sum(1 for line in lines[:5] if ' ' in line and line.strip())
    colon_count = sum(1 for line in lines[:5] if ':' in line and line.strip())

    delimiter = None
    if comma_count > max(semicolon_count, tab_count, space_count, colon_count) and comma_count > 0:
        delimiter = ','
    elif semicolon_count > max(comma_count, tab_count, space_count, colon_count) and semicolon_count > 0:
        delimiter = ';'
    elif tab_count > max(comma_count, semicolon_count, space_count, colon_count) and tab_count > 0:
        delimiter = '\t'
    elif space_count > max(comma_count, semicolon_count, tab_count, colon_count) and space_count > 0:
        delimiter = ' '
    elif colon_count > max(comma_count, semicolon_count, tab_count, space_count) and colon_count > 0:
        delimiter = ':'
    logger.info(f"检测到的分隔符: {delimiter if delimiter else '未检测到，使用正则匹配'}")

    # 解析每一行
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # 使用正则表达式匹配 IP:Port
        match = ip_port_pattern.match(line)
        if match:
            server = match.group(1).strip('[]')  # 去除 IPv6 的方括号
            port = int(match.group(4))
            if 0 <= port <= 65535:
                server_port_pairs.append((server, port))
                logger.debug(f"从正则解析到: {server}:{port}")
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid port range)")
            continue

        # 如果正则未匹配，尝试分隔符解析
        if delimiter:
            fields = line.split(delimiter)
            if len(fields) >= 2:
                server = fields[0].strip('[]')  # 去除可能的方括号
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

    # 去重
    unique_server_port_pairs = list(dict.fromkeys(server_port_pairs))
    logger.info(f"去重后共 {len(unique_server_port_pairs)} 个 server:port 对")
    logger.info(f"解析出的前 5 个 server:port 对: {unique_server_port_pairs[:5]}")

    if invalid_lines:
        logger.info(f"发现 {len(invalid_lines)} 个无效条目: {invalid_lines[:5]}")

    return unique_server_port_pairs

def write_ip_list(ip_ports: List[Tuple[str, int]]) -> str:
    """写入 ip.txt，格式为 'ip port'"""
    if not ip_ports:
        logger.error(f"无有效节点，无法生成 {IP_LIST_FILE}")
        return None
    try:
        with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
            for ip, port in ip_ports:
                f.write(f"{ip} {port}\n")  # 使用空格分隔 IP 和端口
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

        # 定义实时读取输出的函数
        def read_stream(stream, lines, stream_name):
            while True:
                line = stream.readline()
                if not line:
                    break
                print(line.strip())  # 直接打印输出
                lines.append(line)

        # 启动线程分别读取 stdout 和 stderr
        stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, stdout_lines, "stdout"))
        stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, stderr_lines, "stderr"))
        stdout_thread.start()
        stderr_thread.start()

        # 等待线程完成
        stdout_thread.join()
        stderr_thread.join()

        # 等待进程结束
        return_code = process.wait()

        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)
        logger.info(f"iptest.sh stdout: {stdout}")
        if stderr:
            logger.info(f"iptest.sh stderr: {stderr}")

        if return_code != 0:
            logger.error(f"iptest.sh 运行失败，返回码: {return_code}")
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
       
