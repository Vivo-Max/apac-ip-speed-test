"""
从 ip.csv 文件中提取 IP、端口、国家和网络延迟信息，转换为类似 36.50.90.241:47790#🇭🇰香港-1 格式的节点列表，
并按网络延迟升序排列。输出保存到 api.txt。
"""
import logging
import os
import sys
import csv
import re
from collections import defaultdict
from typing import List, Tuple
import time

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("generate_api.log", encoding="utf-8", mode="w"),
        logging.StreamHandler(sys.stdout)
    ],
    force=True
)
logger = logging.getLogger(__name__)
sys.stdout.reconfigure(line_buffering=True)

# 常量
INPUT_CSV = "ip.csv"
OUTPUT_FILE = "api.txt"

# 国家标签（ISO 代码 -> (表情符号, 国家名称)）
COUNTRY_LABELS = {
    'JP': ('🇯🇵', '日本'), 'KR': ('🇰🇷', '韩国'), 'SG': ('🇸🇬', '新加坡'),
    'HK': ('🇭🇰', '香港'), 'ID': ('🇮🇩', '印度尼西亚'), 'IN': ('🇮🇳', '印度'),
    'US': ('🇺🇸', '美国'), 'DE': ('🇩🇪', '德国'), 'FR': ('🇫🇷', '法国'),
    'SE': ('🇸🇪', '瑞典'), 'AT': ('🇦🇹', '奥地利'), 'NL': ('🇳🇱', '荷兰'),
    'PL': ('🇵🇱', '波兰')
}

# 国家别名映射
COUNTRY_ALIASES = {
    'JAPAN': 'JP', '日本': 'JP',
    'SOUTH KOREA': 'KR', 'KOREA': 'KR', '韩国': 'KR',
    'SINGAPORE': 'SG', '新加坡': 'SG',
    'HONG KONG': 'HK', '香港': 'HK',
    'INDONESIA': 'ID', '印尼': 'ID',
    'INDIA': 'IN', '印度': 'IN',
    'UNITED STATES': 'US', 'USA': 'US', '美国': 'US',
    'GERMANY': 'DE', '德国': 'DE',
    'FRANCE': 'FR', '法国': 'FR',
    'SWEDEN': 'SE', '瑞典': 'SE',
    'AUSTRIA': 'AT', '奥地利': 'AT',
    'NETHERLANDS': 'NL', '荷兰': 'NL',
    'POLAND': 'PL', '波兰': 'PL'
}

def is_valid_ip(ip: str) -> bool:
    """验证 IP 地址（支持 IPv4 和 IPv6）"""
    ipv4_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    ipv6_pattern = re.compile(r'^(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$')
    return bool(ipv4_pattern.match(ip) or ipv6_pattern.match(ip.strip('[]')))

def is_valid_port(port: str) -> bool:
    """验证端口号（0-65535）"""
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def parse_delay(delay: str) -> float:
    """解析延迟值（如 '74 ms' -> 74.0），无效时返回 float('inf')"""
    try:
        # 移除 'ms' 并转换为浮点数
        delay_clean = re.sub(r'\s*ms\s*', '', delay.strip(), flags=re.IGNORECASE)
        delay_num = float(delay_clean)
        return delay_num if delay_num >= 0 else float('inf')
    except (ValueError, TypeError):
        return float('inf')

def is_country_like(value: str) -> bool:
    """检查值是否像国家代码或名称"""
    if not value:
        return False
    value_upper = value.upper().strip()
    if re.match(r'^[A-Z]{2}$', value_upper) and value_upper in COUNTRY_LABELS:
        return True
    if value_upper in COUNTRY_ALIASES:
        return True
    value_clean = re.sub(r'[^a-zA-Z\s]', '', value_upper).strip()
    value_clean_no_space = value_clean.replace(' ', '')
    return value_clean in COUNTRY_ALIASES or value_clean_no_space in COUNTRY_ALIASES

def standardize_country(country: str) -> str:
    """标准化国家代码"""
    if not country:
        return ''
    country_clean = re.sub(r'[^a-zA-Z\s]', '', country).strip().upper()
    if country_clean in COUNTRY_LABELS:
        return country_clean
    if country_clean in COUNTRY_ALIASES:
        return COUNTRY_ALIASES[country_clean]
    country_clean_no_space = country_clean.replace(' ', '')
    for alias, code in COUNTRY_ALIASES.items():
        if country_clean_no_space == alias.replace(' ', ''):
            return code
    return ''

def find_column(header: List[str], keywords: List[str]) -> int:
    """查找包含指定关键词的列索引"""
    for idx, col in enumerate(header):
        col_lower = col.strip().lower()
        if col_lower in keywords:
            logger.info(f"检测到 {keywords[0]} 列: 第 {idx + 1} 列 (字段名: {col})")
            return idx
    return -1

def generate_api_txt(csv_file: str) -> int:
    """生成按延迟升序排列的节点列表"""
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在")
        return 0

    final_nodes = []
    try:
        with open(csv_file, "r", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                logger.error(f"{csv_file} 没有有效的表头")
                return 0
            logger.info(f"标头: {header}")

            # 查找列索引
            ip_col = find_column(header, ['ip', 'ip地址', 'address', 'ip_address', 'ip_addr'])
            port_col = find_column(header, ['port', '端口'])
            country_col = find_column(header, ['country', '国家', 'country_code', 'countrycode', '国际代码'])
            delay_col = find_column(header, ['delay', '网络延迟', 'latency', 'ping', 'ms'])

            if ip_col == -1 or port_col == -1:
                logger.error("未找到 IP 或端口列")
                return 0

            # 逐行处理
            for row in reader:
                if len(row) <= max(ip_col, port_col, country_col, delay_col):
                    continue
                ip, port = row[ip_col].strip(), row[port_col].strip()
                if not is_valid_ip(ip) or not is_valid_port(port):
                    continue
                country = standardize_country(row[country_col].strip() if country_col != -1 and country_col < len(row) else '')
                delay = parse_delay(row[delay_col]) if delay_col != -1 and delay_col < len(row) else float('inf')
                final_nodes.append((ip, int(port), country, delay))
    except Exception as e:
        logger.error(f"无法读取 {csv_file}: {e}")
        return 0

    if not final_nodes:
        logger.info(f"没有符合条件的节点")
        return 0

    # 排序：延迟升序，国家代码，IP，端口
    if delay_col == -1:
        logger.warning("未找到延迟列，按国家代码字典序排序")
        sort_key = lambda x: (x[2] or 'ZZ', x[0], x[1])
    else:
        sort_key = lambda x: (x[3], x[2] or 'ZZ', x[0], x[1])

    country_count = defaultdict(int)
    labeled_nodes = []
    for ip, port, country, delay in sorted(final_nodes, key=sort_key):
        if country and country in COUNTRY_LABELS:
            country_count[country] += 1
            emoji, name = COUNTRY_LABELS[country]
            label = f"{emoji}{name}-{country_count[country]}"
        else:
            country_count['UNKNOWN'] += 1
            label = f"🌐未知-{country_count['UNKNOWN']}"
        labeled_nodes.append((ip, port, label))

    # 去重（基于 IP 和端口）
    unique_nodes = []
    seen = set()
    for ip, port, label in labeled_nodes:
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            unique_nodes.append((ip, port, label))

    with open(OUTPUT_FILE, "w", encoding="utf-8-sig") as f:
        for ip, port, label in unique_nodes:
            f.write(f"{ip}:{port}#{label}\n")

    logger.info(f"生成 {OUTPUT_FILE}，{len(unique_nodes)} 个节点 (耗时: {time.time() - start_time:.2f} 秒)")
    logger.info(f"国家分布: {dict(country_count)}")
    return len(unique_nodes)

def main():
    node_count = generate_api_txt(INPUT_CSV)
    if not node_count:
        logger.error("无法生成 api.txt 文件，退出")
        sys.exit(1)
    logger.info("生成完成！")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("用户中断操作，退出")
        sys.exit(1)
    except Exception as e:
        logger.error(f"程序异常: {e}")
        sys.exit(1)