#! /bin/sh

head -n 1000 queryfile-example-10million-201202_part01 | dnsperf -c 5 -T 5 -t 10
