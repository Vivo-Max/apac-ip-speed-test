import csv
import os
import subprocess
import threading
import logging
import ipaddress
from typing import List, Tuple, Optional

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("speedtest.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 文件路径
INPUT_CSV = "input.csv"
IP_LIST_FILE = "ip.txt"
FINAL_CSV = "ip.csv"
FINAL_IPS_FILE = "ips.txt"
SPEEDTEST_SCRIPT = "./iptest.sh"

# 期望的国家代码
DESIRED_COUNTRIES = ['TW', 'JP', 'HK', 'SG', 'KR', 'IN', 'KP', 'VN', 'TH', 'MM']

def is_valid_ip(ip: str) -> bool:
    """验证是否为有效的 IP 地址"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port: str) -> bool:
    """验证是否为有效的端口号"""
    try:
        port_num = int(port)
        return 0 < port_num <= 65535
    except (ValueError, TypeError):
        return False

def extract_ip_ports_from_file(csv_file: str) -> List[Tuple[str, str, str]]:
    """从 CSV 文件中提取 IP、端口和国家代码"""
    server_port_pairs = []
    invalid_entries = []

    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)  # 跳过表头
        for i, row in enumerate(reader):
            if len(row) < 7:  # 确保行有足够的列
                invalid_entries.append(f"Line {i + 1}: {row} (Insufficient columns)")
                continue

            ip, port, _, _, _, country, *_ = row

            if not is_valid_ip(ip):
                invalid_entries.append(f"Line {i + 1}: {row} (Invalid IP)")
                continue
            if not is_valid_port(port):
                invalid_entries.append(f"Line {i + 1}: {row} (Invalid port)")
                continue

            server_port_pairs.append((ip, port, country))

    # 去重
    unique_server_port_pairs = list(dict.fromkeys(server_port_pairs))
    logger.info(f"去重后共 {len(unique_server_port_pairs)} 个 server:port 对")

    if invalid_entries:
        for entry in invalid_entries:
            logger.info(f"发现无效条目： {entry}")

    return unique_server_port_pairs

def write_ip_list(server_port_pairs: List[Tuple[str, str, str]]) -> None:
    """将 IP:port 对写入 ip.txt，仅包含 DESIRED_COUNTRIES 中的节点"""
    filtered_nodes = [(server, port, country) for server, port, country in server_port_pairs if country in DESIRED_COUNTRIES]
    with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
        for server, port, country in filtered_nodes:
            f.write(f"{server}:{port}\n")
    logger.info(f"生成 {IP_LIST_FILE}，包含 {len(filtered_nodes)} 个节点")

def run_speed_test() -> Optional[str]:
    """运行测速脚本"""
    if not os.path.exists(SPEEDTEST_SCRIPT):
        logger.error(f"测速脚本 {SPEEDTEST_SCRIPT} 不存在")
        return None
    if not os.access(SPEEDTEST_SCRIPT, os.X_OK):
        logger.error(f"测速脚本 {SPEEDTEST_SCRIPT} 不可执行")
        return None
    if not os.path.exists(IP_LIST_FILE):
        logger.error(f"IP 列表文件 {IP_LIST_FILE} 不存在")
        return None

    try:
        # 直接调用 iptest.sh，参数已经在 iptest.sh 中硬编码
        cmd = [SPEEDTEST_SCRIPT]
        logger.info(f"运行测速命令: {' '.join(cmd)}")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        stdout_lines = []
        stderr_lines = []

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

        return_code = process.wait()
        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)
        logger.info(f"iptest.sh stdout: {stdout}")
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

def filter_speed_and_deduplicate(csv_file: str) -> List[List[str]]:
    """过滤测速结果并去重"""
    rows = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows.extend(reader)

    # 去重（基于 IP 和端口）
    seen = set()
    final_rows = []
    for row in rows:
        if len(row) < 4:  # 假设包含 IP、端口、延迟、下载速度
            continue
        key = (row[0], row[1])
        if key not in seen:
            seen.add(key)
            final_rows.append(row)

    with open(csv_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(final_rows)

    logger.info(f"去重完成，{csv_file} 包含 {len(final_rows)} 条记录")
    return final_rows

def generate_ips_file(csv_rows: List[List[str]]) -> None:
    """生成最终的 ips.txt 文件，仅包含 DESIRED_COUNTRIES 中的节点"""
    final_nodes = []
    for row in csv_rows:
        if len(row) < 7:  # 确保有足够的列
            continue
        ip, port, _, _, _, country, *_ = row
        if not is_valid_ip(ip) or not is_valid_port(port):
            logger.debug(f"无效 IP 或端口: {ip}:{port}")
            continue
        if country in DESIRED_COUNTRIES:
            final_nodes.append((ip, int(port), country))

    with open(FINAL_IPS_FILE, "w", encoding="utf-8") as f:
        for ip, port, country in final_nodes:
            f.write(f"{ip}:{port}\n")

    logger.info(f"生成 {FINAL_IPS_FILE}，包含 {len(final_nodes)} 个节点")

def main():
    """主函数"""
    # 检查输入文件是否存在
    if not os.path.exists(INPUT_CSV):
        logger.error(f"输入文件 {INPUT_CSV} 不存在")
        return

    # 提取 IP 和端口
    server_port_pairs = extract_ip_ports_from_file(INPUT_CSV)
    if not server_port_pairs:
        logger.error("未提取到有效的 IP:port 对，退出")
        return

    # 写入 ip.txt
    write_ip_list(server_port_pairs)

    # 运行测速
    csv_file = run_speed_test()
    if not csv_file:
        logger.error("测速失败，退出")
        return

    # 去重测速结果
    csv_rows = filter_speed_and_deduplicate(csv_file)

    # 生成最终的 ips.txt
    generate_ips_file(csv_rows)

if __name__ == "__main__":
    main()
