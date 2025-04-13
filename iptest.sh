   #!/bin/bash

   ./iptest -file=ip.txt -tls=true -speedtest=3 -speedlimit=8 timeout=10 -url="speed.cloudflare.com/__down?bytes=1000000" -max=10 -outfile="ip.csv"
