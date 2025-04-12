name: Proxy IP Check

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main
  schedule:
    - cron: '0 0 * * *'  # 每天 UTC 00:00 运行
  workflow_dispatch:  # 支持手动触发

jobs:
  check-proxy-ip:
    runs-on: ubuntu-latest

    steps:
      # 检出代码
      - name: Checkout repository
        uses: actions/checkout@v4

      # 检查 input.csv 是否存在
      - name: Check for input.csv
        run: |
          if [ ! -f "input.csv" ]; then
            echo "Error: input.csv not found! Please upload input.csv to the repository."
            exit 1
          fi

      # 设置 Python 环境
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.x'

      # 安装依赖
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install requests charset-normalizer

      # 确保测速工具存在并可执行
      - name: Prepare speedtest script
        run: |
          if [ -f "iptest.sh" ]; then
            chmod +x iptest.sh
          else
            echo "iptest.sh not found!"
            exit 1
          fi
          if [ -f "iptest" ]; then
            chmod +x iptest
          else
            echo "iptest binary not found!"
            exit 1
          fi

      # 运行脚本，带重试机制
      - name: Run proxy IP check
        uses: nick-invision/retry@v3
        with:
          timeout_minutes: 30
          max_attempts: 2
          command: python ip-filter-speedtest-api.py

      # 上传结果文件
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: proxy-ip-results
          path: |
            ip.txt
            ip.csv
            ips.txt
            country_cache.json
          if-no-files-found: warn

      # 清理缓存文件
      - name: Clean up
        if: always()
        run: |
          rm -f country_cache.json
