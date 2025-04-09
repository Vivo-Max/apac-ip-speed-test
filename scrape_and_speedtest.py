import requests
import re
import csv
import subprocess
import os
from typing import List, Tuple

# 配置
URL = "https://bihai.cf/CFIP/CUCC/standard.csv"  # 如果有 URL，替换为实际地址；否则需手动提供 CSV 内容
IP_LIST_FILE = "ip.txt"
SPEEDTEST_TOOL = "./iptest"  # 使用存储库中的 iptest 二进制
FINAL_CSV = "result.csv"
MIN_SPEED_MBPS = 0.1  # 最低速度 0.1 MB/s，手动过滤

# 亚太区国家代码（不包括 AU 和 NZ）
ASIA_PACIFIC_REGIONS = {
    'JP', 'KR', 'SG', 'TW', 'HK', 'MY', 'TH', 'ID', 'PH',
    'VN', 'IN', 'MO', 'BN', 'KH', 'LA', 'MM', 'TL'
}
COUNTRY_MAPPING = {
    '台湾': 'TW', '日本': 'JP', '韩国': 'KR', '新加坡': 'SG', '香港': 'HK',
    '马来西亚': 'MY', '泰国': 'TH', '印度尼西亚': 'ID', '菲律宾': 'PH',
    '越南': 'VN', '印度': 'IN', '澳门': 'MO', '文莱': 'BN',
    '柬埔寨': 'KH', '老挝': 'LA', '缅甸': 'MM', '东帝汶': 'TL'
}

def fetch_content(url: str) -> str:
    """从 URL 下载内容"""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"下载内容失败: {e}")
        return None

def extract_ip_ports(content: str) -> List[Tuple[str, str, str]]:
    """提取 IP、端口和国家代码，只保留亚太区节点"""
    ip_pattern = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    port_pattern = r"(?:\b|_|:)([0-9]{1,5})\b"
    country_pattern = r"(?:[A-Z]{2}|\b(?:台湾|日本|韩国|新加坡|香港|马来西亚|泰国|印度尼西亚|菲律宾|越南|印度|澳门|文莱|柬埔寨|老挝|缅甸|东帝汶))\b"

    ip_ports = []
    lines = content.splitlines()
    for line in lines:
        ips = re.findall(ip_pattern, line)
        if not ips:
            continue
        country_match = re.search(country_pattern, line)
        country = COUNTRY_MAPPING.get(country_match.group(0), country_match.group(0).upper()) if country_match else None
        if country not in ASIA_PACIFIC_REGIONS:
            continue
        for ip in ips:
            ports = re.findall(port_pattern, line)
            port = next((p for p in ports if 1 <= int(p) <= 65535), "443")
            ip_ports.append((ip, port, country))
    return ip_ports

def write_ip_list(ip_ports: List[Tuple[str, str, str]]) -> str:
    """写入 ip.txt"""
    with open(IP_LIST_FILE, "w", encoding="utf-8") as f:
        for ip, port, _ in ip_ports:
            f.write(f"{ip} {port}\n")
    print(f"生成 {IP_LIST_FILE}，包含 {len(ip_ports)} 个节点")
    return IP_LIST_FILE

def run_speed_test(ip_file: str) -> str:
    """运行测速"""
    try:
        cmd = [
            SPEEDTEST_TOOL,
            "-file", ip_file,
            "-outfile", FINAL_CSV,
            "-speedtest", "5",
            "-url", "https://speed.cloudflare.com/__down?bytes=500000"  # 500KB 文件
            # 移除 -speedlimit 参数
        ]
        print(f"运行测速命令: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(f"iptest stdout: {result.stdout}")
        print(f"iptest stderr: {result.stderr}")
        if result.returncode == 0:
            if os.path.exists(FINAL_CSV):
                print(f"测速完成，结果保存到 {FINAL_CSV}")
                return FINAL_CSV
            else:
                print(f"测速完成，但 {FINAL_CSV} 未生成，可能是没有符合条件的节点")
                return None
        else:
            print(f"测速失败: {result.stderr}")
            return None
    except Exception as e:
        print(f"运行测速失败: {e}")
        return None

def filter_speed_and_deduplicate(csv_file: str, min_speed: float):
    """过滤速度低于 min_speed 的节点并去重"""
    if not os.path.exists(csv_file):
        print(f"{csv_file} 不存在，跳过过滤和去重")
        return
    seen = set()
    final_rows = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        # 假设速度在第 3 列（根据 iptest 输出格式调整）
        speed_idx = 2  # 可能需要根据实际 CSV 格式调整
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
        print(f"没有节点的速度高于 {min_speed} MB/s，删除 {csv_file}")
        os.remove(csv_file)
        return

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(final_rows)
    print(f"过滤和去重完成，{csv_file} 包含 {len(final_rows)} 条记录")

def main():
    # 如果有 URL，直接抓取；否则需手动提供 CSV 内容
    content = fetch_content(URL)
    if not content:
        # 如果没有 URL，可以手动读取本地 CSV 文件
        try:
            with open("input.csv", "r", encoding="utf-8") as f:
                content = f.read()
            print("从本地 input.csv 读取内容")
        except FileNotFoundError:
            print("无 URL 且本地 input.csv 不存在，程序退出")
            exit(1)

    # 提取亚太区节点
    ip_ports = extract_ip_ports(content)
    if not ip_ports:
        print("未找到符合条件的亚太区节点")
        exit(1)
    print(f"提取到 {len(ip_ports)} 个亚太区节点")

    # 写入 ip.txt
    ip_file = write_ip_list(ip_ports)

    # 一次性测速
    csv_file = run_speed_test(ip_file)
    if csv_file:
        # 过滤速度并去重
        filter_speed_and_deduplicate(csv_file, MIN_SPEED_MBPS)
        if not os.path.exists(csv_file):
            print("无符合速度条件的节点")
    else:
        print("无测速结果")

if __name__ == "__main__":
    main()
