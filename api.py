import logging
import os
import sys
from typing import List, Tuple
from collections import defaultdict
import csv
import time
import re

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
    'KE': ('🇰🇪', '肯尼亚'), 'GH': ('🇬🇭', '加纳'), 'MA': ('🇲🇪', '摩洛哥'),
    'DZ': ('🇩🇿', '阿尔及利亚'), 'TN': ('🇹🇳', '突尼斯'), 'AR': ('🇦🇷', '阿根廷'),
    'CL': ('🇨🇱', '智利'), 'CO': ('🇨🇴', '哥伦比亚'), 'PE': ('🇵🇪', '秘鲁'),
    'MX': ('🇲🇽', '墨西哥'), 'VE': ('🇻🇪', '委内瑞拉'), 'SE': ('🇸🇪', '瑞典'),
    'NO': ('🇳🇴', '挪威'), 'DK': ('🇩🇰', '丹麦'), 'CH': ('🇨🇭', '瑞士'),
    'AT': ('🇦🇹', '奥地利'), 'BE': ('🇧🇪', '比利时'), 'IE': ('🇮🇪', '爱尔兰'),
    'PT': ('🇵🇹', '葡萄牙'), 'GR': ('🇬🇷', '希腊'), 'BG': ('🇬🇧', '保加利亚'),
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
    # 匹配 ISO 3166-1 alpha-2 代码
    if re.match(r'^[A-Z]{2}$', value_upper) and value_upper in COUNTRY_LABELS:
        return True
    # 匹配别名
    if value_upper in COUNTRY_ALIASES:
        return True
    # 移除非字母字符后匹配
    value_clean = re.sub(r'[^a-zA-Z\s]', '', value_upper).strip()
    if value_clean in COUNTRY_ALIASES:
        return True
    value_clean_no_space = value_clean.replace(' ', '')
    for alias in COUNTRY_ALIASES:
        alias_clean = alias.replace(' ', '')
        if value_clean_no_space == alias_clean:
            return True
    return False

def standardize_country(country: str) -> str:
    if not country:
        return ''
    # 清理非字母字符并转换为大写
    country_clean = re.sub(r'[^a-zA-Z\s]', '', country).strip().upper()
    # 直接匹配 ISO 代码
    if country_clean in COUNTRY_LABELS:
        return country_clean
    # 匹配别名
    if country_clean in COUNTRY_ALIASES:
        return COUNTRY_ALIASES[country_clean]
    # 移除空格后匹配别名
    country_clean_no_space = country_clean.replace(' ', '')
    for alias, code in COUNTRY_ALIASES.items():
        alias_clean = alias.replace(' ', '')
        if country_clean_no_space == alias_clean:
            return code
    return ''

def find_country_column(header: List[str]) -> int:
    country_col = -1
    for idx, col in enumerate(header):
        col_lower = col.strip().lower()
        if col_lower in ['country', '国家', 'country_code', 'countrycode', '国际代码', 'nation', 'location', 'region', 'geo', 'area']:
            country_col = idx
            logger.info(f"检测到国家列: 第 {idx + 1} 列 (字段名: {col})")
            break
    return country_col

def extract_country_from_row(row: List[str], country_col: int) -> str:
    # 优先检查指定的国家列
    if country_col != -1 and country_col < len(row):
        country = standardize_country(row[country_col].strip())
        if country:
            return country
    # 如果国家列为空或未指定，逐列搜索
    for col, field in enumerate(row):
        field = field.strip()
        if is_country_like(field):
            country = standardize_country(field)
            if country:
                logger.info(f"从第 {col + 1} 列提取国家: {field} -> {country}")
                return country
    return ''

def generate_api_txt(csv_file: str) -> int:
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在")
        return 0

    final_nodes = []
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            # 读取标头
            header = next(reader, None)
            if not header:
                logger.error(f"{csv_file} 没有有效的表头")
                return 0
            logger.info(f"标头: {header}")

            # 确定国家列
            country_col = find_country_column(header)

            # 确定 IP 和端口列（假设前两列）
            ip_col, port_col = 0, 1

            # 逐行处理
            for row in reader:
                if len(row) < 2:
                    continue
                ip, port = row[ip_col], row[port_col]
                if not is_valid_ip(ip) or not is_valid_port(port):
                    continue
                # 提取国家信息
                country = extract_country_from_row(row, country_col)
                final_nodes.append((ip, int(port), country))
    except Exception as e:
        logger.error(f"无法读取 {csv_file}: {e}")
        return 0

    if not final_nodes:
        logger.info(f"没有符合条件的节点")
        return 0

    country_count = defaultdict(int)
    labeled_nodes = []
    # 按国家代码排序，未知国家排在最后
    for ip, port, country in sorted(final_nodes, key=lambda x: x[2] or 'ZZ'):
        if country and country in COUNTRY_LABELS:
            country_count[country] += 1
            emoji, name = COUNTRY_LABELS[country]
            label = f"{emoji}{name}-{country_count[country]}"
            labeled_nodes.append((ip, port, label))
        else:
            labeled_nodes.append((ip, port, "🌐未知"))

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