   #!/bin/bash

   ./iptest -file=ip.txt -tls=true -speedtest=10 -speedlimit=5 -url="speed.cloudflare.com/__down?bytes=50000000" -max=200 -outfile="ip.csv"
