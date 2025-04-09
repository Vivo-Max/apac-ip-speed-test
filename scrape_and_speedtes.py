import requests
import re
import csv
import subprocess
import os
from typing import List, Tuple

# 配置
URL = "https://bihai.cf/CFIP/CUCC/standard.csv"  # 如果有 URL，替换为实际地址；否则需手动提供 CSV 内容
IP_LIST_FILE = "ip.txt"
SPEEDTEST_TOOL = "./iptest"  # 使用 iptest 二进制
FINAL_CSV = "result.csv"

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
            "-speedtest", "10",  # 10 个线程
            "-url", "https://speed.cloudflare.com/__down?bytes=1000000",  # 1MB 文件
            "-min-speed", "1"  # 筛选速度 ≥ 1 MB/s
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"测速完成，结果保存到 {FINAL_CSV}")
        else:
            print(f"测速失败: {result.stderr}")
        return FINAL_CSV
    except Exception as e:
        print(f"运行测速失败: {e}")
        return None

def deduplicate_csv(csv_file: str):
    """去重 CSV 文件"""
    if not os.path.exists(csv_file):
        return
    seen = set()
    final_rows = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        for row in reader:
            key = (row[0], row[1])  # 以 IP 和 Port 去重
            if key not in seen:
                seen.add(key)
                final_rows.append(row)

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(final_rows)
    print(f"去重完成，{csv_file} 包含 {len(final_rows)} 条记录")

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
        # 去重
        deduplicate_csv(csv_file)
    else:
        print("无测速结果")

if __name__ == "__main__":
    main()