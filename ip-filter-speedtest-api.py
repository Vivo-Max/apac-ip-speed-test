import argparse
import codecs
import logging
import os
import re
import subprocess
import sys
import requests
from typing import List, Tuple

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# 常量
INPUT_FILE = "input.csv"
IP_LIST_FILE = "ip.txt"
SPEEDTEST_CSV = "ip.csv"
IPS_FILE = "ips.txt"
URL = "YOUR_URL_HERE"  # 替换为实际的 URL

def is_valid_ip(ip: str) -> bool:
    """验证 IP 地址是否有效（IPv4 或 IPv6）"""
    ipv4_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$'
    return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))

def is_valid_port(port: str) -> bool:
    """验证端口号是否有效"""
    try:
        port_num = int(port)
        return 0 < port_num <= 65535
    except ValueError:
        return False

def standardize_country(country: str) -> str:
    """标准化国家代码或名称"""
    if not country:
        return ''
    country = country.strip().upper()
    country_map = {
        'HK': 'HK', 'HKG': 'HK', '香港': 'HK',
        'TW': 'TW', 'TPE': 'TW', '台湾': 'TW', '台北': 'TW',
        'JP': 'JP', 'JPN': 'JP', '日本': 'JP', '东京': 'JP',
        'SG': 'SG', 'SIN': 'SG', '新加坡': 'SG',
        'CN': 'CN', 'CHN': 'CN', '中国': 'CN',
        'US': 'US', 'USA': 'US', '美国': 'US',
        'KR': 'KR', 'KOR': 'KR', '韩国': 'KR'
    }
    return country_map.get(country, '')

def is_country_like(value: str) -> bool:
    """判断值是否像国家代码或名称"""
    if not value:
        return False
    value = value.strip().upper()
    country_keywords = {'HK', 'HKG', 'TW', 'TPE', 'JP', 'JPN', 'SG', 'SIN', 'CN', 'CHN', 'US', 'USA', 'KR', 'KOR',
                        '香港', '台湾', '台北', '日本', '东京', '新加坡', '中国', '美国', '韩国'}
    return value in country_keywords

def detect_delimiter(lines: List[str]) -> str:
    """检测 CSV 文件的分隔符"""
    if not lines:
        return ''
    first_line = lines[0]
    for delim in [',', '\t', ';', '|']:
        if delim in first_line:
            return delim
    return ','

def find_country_column(lines: List[str], delimiter: str) -> Tuple[int, int, int]:
    """通过遍历行列找到 IP、端口和国家列"""
    ip_col, port_col, country_col = 0, 1, -1
    country_candidates = {}
    for line in lines[:50]:  # 检查前 50 行
        if not line.strip() or line.startswith('#'):
            continue
        fields = line.split(delimiter)
        for col, field in enumerate(fields):
            field = field.strip()
            if is_country_like(field):
                country_candidates[col] = country_candidates.get(col, 0) + 1
    if country_candidates:
        country_col = max(country_candidates, key=country_candidates.get)
        total_lines = sum(1 for line in lines if line.strip() and not line.startswith('#'))
        match_rate = country_candidates[country_col] / total_lines if total_lines > 0 else 0
        if match_rate > 0.5:  # 匹配率大于 50%
            logger.info(f"通过遍历确定国家列：第 {country_col + 1} 列 (匹配率：{match_rate:.2%})")
        else:
            country_col = -1
    return ip_col, port_col, country_col

def extract_ip_ports_from_file(file_path: str, encoding: str = 'utf-8') -> List[Tuple[str, int, str]]:
    """从本地文件提取 IP、端口和国家（若存在）"""
    server_port_pairs = []
    invalid_lines = []

    if not os.path.exists(file_path):
        logger.error(f"文件 {file_path} 不存在")
        return []

    # 读取原始字节
    with open(file_path, "rb") as f:
        raw_data = f.read()
    if not raw_data:
        logger.error(f"文件 {file_path} 为空")
        return []

    # 检测并移除 BOM
    if raw_data.startswith(codecs.BOM_UTF8):
        logger.info(f"检测到 UTF-8 BOM，移除")
        raw_data = raw_data[len(codecs.BOM_UTF8):]

    # 优先使用指定的编码（默认 UTF-8）
    try:
        content = raw_data.decode(encoding, errors='strict')
        logger.info(f"成功使用编码 {encoding} 解码文件 {file_path}")
    except UnicodeDecodeError as e:
        logger.error(f"使用 {encoding} 解码失败: {e}")
        # 尝试其他常见编码
        fallback_encodings = ['gbk', 'big5', 'utf-16']
        for enc in fallback_encodings:
            try:
                content = raw_data.decode(enc, errors='strict')
                logger.info(f"成功使用备用编码 {enc} 解码文件 {file_path}")
                break
            except UnicodeDecodeError:
                continue
        else:
            logger.error(f"无法解码文件 {file_path}，尝试的编码: {[encoding] + fallback_encodings}")
            return []

    logger.info(f"从本地文件 {file_path} 读取内容 (长度: {len(content)} 字节，编码: {encoding})")
    logger.debug(f"文件 {file_path} 内容前5行: {content.splitlines()[:5]}")

    # 替换换行符
    content = content.replace('\r\n', '\n').replace('\r', '\n')
    lines = content.splitlines()

    delimiter = detect_delimiter(lines)
    logger.info(f"检测到的分隔符: {delimiter if delimiter else '未检测到，使用正则匹配'}")
    if not delimiter:
        return []

    ip_col, port_col, country_col = 0, 1, -1
    lines_to_process = lines
    if lines and lines[0].strip() and not lines[0].startswith('#'):
        header = lines[0].strip().split(delimiter)
        for idx, col in enumerate(header):
            col_lower = col.strip().lower()
            if col_lower in ['ip', 'address', 'ip地址', '节点']:
                ip_col = idx
            elif col_lower in ['port', '端口', '端口口']:
                port_col = idx
            elif col_lower in ['country', '国家', 'code', 'nation', 'location', '国际代码']:
                country_col = idx
        if country_col != -1:
            logger.info(f"通过表头确定国家列: 第 {country_col + 1} 列 ({header[country_col]})")
            lines_to_process = lines[1:]
        else:
            logger.info("表头中未找到国家列，尝试遍历行列")
            ip_col, port_col, country_col = find_country_column(lines, delimiter)

    ip_port_pattern = re.compile(r'(((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\]|(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))[ :,\t](\d{1,5})')

    for i, line in enumerate(lines_to_process):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        match = ip_port_pattern.match(line)
        if match:
            server = match.group(1).strip('[]')
            port = int(match.group(4))
            country = ''
            if country_col != -1:
                fields = line.split(delimiter)
                if country_col < len(fields):
                    country = standardize_country(fields[country_col].strip())
                    if not country:
                        logger.warning(f"检测到可能的乱码国家: {fields[country_col]}，跳过")
                        continue
            if is_valid_port(str(port)):
                server_port_pairs.append((server, port, country))
                logger.debug(f"解析到: {server}:{port}, 国家: {country or '无'}")
            else:
                invalid_lines.append(f"Line {i}: {line} (Invalid port range)")
            continue

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
                logger.warning(f"检测到可能的乱码国家: {fields[country_col]}，跳过")
                continue
        else:
            for col, field in enumerate(fields):
                field = field.strip()
                if is_country_like(field):
                    country = standardize_country(field)
                    if country:
                        logger.debug(f"逐行找到国家: {field} -> {country} (第 {col + 1} 列)")
                        break

        if is_valid_ip(server) and is_valid_port(port_str):
            server_port_pairs.append((server, int(port_str), country))
            logger.debug(f"解析到: {server}:{port_str}, 国家: {country or '无'}")
        else:
            invalid_lines.append(f"Line {i}: {line} (Invalid IP or port)")

    logger.info(f"从文件解析到 {len(server_port_pairs)} 个记录")
    if not server_port_pairs:
        logger.error("未解析到有效 IP，可能原因：文件数据无效或格式错误")
    if invalid_lines:
        logger.info(f"发现 {len(invalid_lines)} 个无效条目: {invalid_lines[:5]}")

    return server_port_pairs

def fetch_and_extract_ip_ports_from_url(url: str) -> List[Tuple[str, int, str]]:
    """从 URL 获取 IP 和端口（假设实现）"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text
        # 假设内容是 CSV 格式，保存为临时文件并调用 extract_ip_ports_from_file
        with open("temp.csv", "w", encoding="utf-8") as f:
            f.write(content)
        ip_ports = extract_ip_ports_from_file("temp.csv")
        os.remove("temp.csv")
        return ip_ports
    except Exception as e:
        logger.error(f"从 URL 获取 IP 失败: {e}")
        return []

def check_dependencies() -> None:
    """检查依赖（假设实现）"""
    required_commands = ['iptest']
    for cmd in required_commands:
        try:
            subprocess.run([cmd, '--version'], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            logger.error(f"依赖 {cmd} 未安装或不可用")
            sys.exit(1)

def write_ip_list(ip_ports: List[Tuple[str, int, str]]) -> str:
    """将 IP 和端口写入 ip.txt"""
    try:
        with open(IP_LIST_FILE, 'w', encoding='utf-8') as f:
            for ip, port, _ in ip_ports:
                f.write(f"{ip} {port}\n")
        logger.info(f"已生成 {IP_LIST_FILE}，包含 {len(ip_ports)} 个记录")
        return IP_LIST_FILE
    except Exception as e:
        logger.error(f"写入 {IP_LIST_FILE} 失败: {e}")
        return ''

def run_speed_test() -> str:
    """运行测速（调用 iptest.sh）"""
    try:
        cmd = [
            "./iptest.sh",
            f"-file={IP_LIST_FILE}",
            "-tls=true",
            "-speedtest=5",
            "-speedlimit=10",
            "-url=speed.cloudflare.com/__down?bytes=50000000",
            "-max=200",
            f"-outfile={SPEEDTEST_CSV}"
        ]
        logger.info(f"运行测速命令: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.info(f"测速完成，输出文件: {SPEEDTEST_CSV}")
        logger.debug(f"iptest.sh stdout: {result.stdout}")
        logger.debug(f"iptest.sh stderr: {result.stderr}")
        return SPEEDTEST_CSV
    except subprocess.CalledProcessError as e:
        logger.error(f"测速失败: {e}")
        logger.error(f"iptest.sh stderr: {e.stderr}")
        return ''
    except Exception as e:
        logger.error(f"运行测速命令时发生未知错误: {e}")
        return ''

def filter_speed_and_deduplicate(csv_file: str) -> None:
    """根据速度过滤并去重（假设实现）"""
    try:
        if not os.path.exists(csv_file):
            logger.error(f"测速结果文件 {csv_file} 不存在")
            return
        # 假设 CSV 文件格式：IP,Port,Speed
        records = []
        with open(csv_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for line in lines[1:]:  # 跳过表头
                fields = line.strip().split(',')
                if len(fields) >= 3:
                    ip, port, speed = fields[0], fields[1], float(fields[2])
                    if speed >= 10:  # 速度阈值 10 MB/s
                        records.append((ip, port, speed))
        # 按速度降序排序并去重
        records.sort(key=lambda x: x[2], reverse=True)
        seen = set()
        unique_records = []
        for ip, port, speed in records:
            key = (ip, port)
            if key not in seen:
                seen.add(key)
                unique_records.append((ip, port, speed))
        # 写回文件
        with open(csv_file, 'w', encoding='utf-8') as f:
            f.write("IP,Port,Speed\n")
            for ip, port, speed in unique_records:
                f.write(f"{ip},{port},{speed}\n")
        logger.info(f"过滤并去重完成，保留 {len(unique_records)} 个记录")
    except Exception as e:
        logger.error(f"过滤并去重失败: {e}")

def generate_ips_file(csv_file: str) -> None:
    """生成 ips.txt（假设实现）"""
    try:
        if not os.path.exists(csv_file):
            logger.error(f"测速结果文件 {csv_file} 不存在")
            return
        with open(csv_file, 'r', encoding='utf-8') as f_in, open(IPS_FILE, 'w', encoding='utf-8') as f_out:
            lines = f_in.readlines()
            for line in lines[1:]:  # 跳过表头
                fields = line.strip().split(',')
                if len(fields) >= 2:
                    ip, port = fields[0], fields[1]
                    f_out.write(f"{ip} {port}\n")
        logger.info(f"已生成 {IPS_FILE}")
    except Exception as e:
        logger.error(f"生成 {IPS_FILE} 失败: {e}")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="Proxy IP Speed Test Script")
    parser.add_argument('--encoding', type=str, default='utf-8', help='Specify the encoding of input.csv (e.g., utf-8, gbk)')
    args = parser.parse_args()

    try:
        check_dependencies()
        logger.info("开始执行主流程")
        ip_ports = []
        if os.path.exists(INPUT_FILE):
            logger.info(f"从 {INPUT_FILE} 获取 IP")
            ip_ports = extract_ip_ports_from_file(INPUT_FILE, encoding=args.encoding)
        else:
            logger.info(f"本地文件 {INPUT_FILE} 不存在，尝试从 URL 获取 IP: {URL}")
            ip_ports = fetch_and_extract_ip_ports_from_url(URL)
        logger.info(f"获取到 {len(ip_ports)} 个 IP 记录")
        if not ip_ports:
            logger.error("未获取到有效的 IP 和端口")
            sys.exit(1)
        ip_list_file = write_ip_list(ip_ports)
        if not ip_list_file:
            logger.error("生成 ip.txt 失败")
            sys.exit(1)
        csv_file = run_speed_test()
        if not csv_file:
            logger.error("测速失败")
            sys.exit(1)
        filter_speed_and_deduplicate(csv_file)
        generate_ips_file(csv_file)
    except Exception as e:
        logger.error(f"主流程异常: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
