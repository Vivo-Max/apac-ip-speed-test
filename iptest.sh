   #!/bin/bash

   ./iptest -file=ip.txt -tls=true -speedtest=5 -speedlimit=8 -url="speed.cloudflare.com/__down?bytes=500000000" -max=100 -outfile="ip.csv"
