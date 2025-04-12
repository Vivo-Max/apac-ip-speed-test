def filter_speed_and_deduplicate(csv_file: str):
    """去重 ip.csv 中的节点"""
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在，跳过去重")
        return
    seen = set()
    final_rows = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
            # 假设 ip.csv 的列为 IP,Port,Datacenter,Region,City,Latency,DownloadSpeed
            if len(header) < 7:
                logger.error(f"{csv_file} 表头列数不足: {header}")
                return
        except StopIteration:
            logger.error(f"{csv_file} 为空，跳过去重")
            return
        for row in reader:
            if len(row) < 7:  # 确保行有足够列
                logger.debug(f"跳过无效行: {row}")
                continue
            key = (row[0], row[1])  # 去重基于 IP 和 Port
            if key not in seen:
                seen.add(key)
                final_rows.append(row)

    if not final_rows:
        logger.info(f"没有符合条件的节点，删除 {csv_file}")
        os.remove(csv_file)
        return

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)  # 保留原始表头
        writer.writerows(final_rows)
    logger.info(f"去重完成，{csv_file} 包含 {len(final_rows)} 条记录")

def generate_ips_file(csv_file: str, ip_ports: List[Tuple[str, str, str]]):
    """从 ip.csv 读取 IP 和端口，添加国家标签并写入 ips.txt"""
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在，跳过生成 {IPS_FILE}")
        return

    # 创建 IP:Port 到国家的映射
    ip_port_to_country = {(ip, port): country for ip, port, country in ip_ports}

    # 读取 ip.csv，获取测速后的 IP 和端口
    final_nodes = []
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
            # 假设 ip.csv 的列为 IP,Port,Datacenter,Region,City,Latency,DownloadSpeed
            if len(header) < 7:
                logger.error(f"ip.csv 表头列数不足: {header}")
                return
        except StopIteration:
            logger.error(f"ip.csv 为空，跳过生成 {IPS_FILE}")
            return
        for row in reader:
            if len(row) < 7:  # 确保行有足够列
                logger.debug(f"跳过无效行: {row}")
                continue
            ip, port = row[0], row[1]
            key = (ip, port)
            if key in ip_port_to_country:
                country = ip_port_to_country[key]
                final_nodes.append((ip, port, country))
            else:
                logger.debug(f"未找到 {ip}:{port} 的国家标签，跳过")

    if not final_nodes:
        logger.info(f"没有符合条件的节点，跳过生成 {IPS_FILE}")
        return

    # 统计每个国家的出现次数，为重复国家添加序号
    country_count = defaultdict(int)
    labeled_nodes = []
    for ip, port, country in final_nodes:
        country_count[country] += 1
        emoji, name = COUNTRY_LABELS.get(country, ('🌐', country))
        label = f"{emoji}{name}-{country_count[country]}"
        labeled_nodes.append((ip, port, label))

    # 写入 ips.txt
    with open(IPS_FILE, "w", encoding="utf-8") as f:
        for ip, port, label in labeled_nodes:
            f.write(f"{ip}:{port}#{label}\n")
    logger.info(f"生成 {IPS_FILE}，包含 {len(labeled_nodes)} 个节点")
