#!/bin/sh
service iptables stop
redis-server redis.conf
python dc-daemon
python dc-update-daemon 2>>log
python -m SimpleHTTPServer
