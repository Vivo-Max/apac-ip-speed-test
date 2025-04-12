import speedtest
import csv

def run_speed_test() -> str:
    """使用 speedtest-cli 进行测速"""
    if not os.path.exists(IP_LIST_FILE):
        logger.error(f"IP 列表文件 {IP_LIST_FILE} 不存在")
        return None

    # 读取 IP 和端口
    servers = []
    with open(IP_LIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                ip, port = line.strip().split()
                servers.append((ip, int(port)))

    # 初始化 speedtest
    st = speedtest.Speedtest()
    results = []

    for ip, port in servers[:200]:  # 限制最大 200 个节点
        try:
            logger.info(f"测速 {ip}:{port}")
            # 配置代理（如果需要）
            st.download_url = "speed.cloudflare.com/__down?bytes=50000000"
            st.download()
            download_speed = st.results.download / 1_000_000  # 转换为 Mbps
            if download_speed < 10:  # 速度下限 10 Mbps
                logger.debug(f"{ip}:{port} 速度 {download_speed:.2f} Mbps，低于 10 Mbps，过滤")
                continue
            latency = st.results.ping  # 延迟（ms）
            results.append([ip, port, latency, download_speed])
            logger.info(f"{ip}:{port} 速度: {download_speed:.2f} Mbps, 延迟: {latency:.2f} ms")
        except Exception as e:
            logger.error(f"测速 {ip}:{port} 失败: {e}")
            continue

    if not results:
        logger.error("无有效测速结果")
        return None

    # 保存结果到 ip.csv
    with open(FINAL_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Port", "Latency(ms)", "Download(Mbps)"])
        writer.writerows(results)

    logger.info(f"测速完成，结果保存到 {FINAL_CSV}")
    return FINAL_CSV
