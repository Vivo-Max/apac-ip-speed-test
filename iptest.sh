   #!/bin/bash

   ./iptest -file=ip.txt -tls=true -speedtest=2 -speedlimit=8 timeout=5 -url="speed.cloudflare.com/__down?bytes=1000000" -max=100 -outfile="ip.csv"
