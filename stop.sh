#!/bin/sh
kill -9 `ps ax|grep python|grep SimpleHTTPServer|awk '{print $1}'`
kill -9 `ps ax|grep dc|grep daemon|awk '{print $1}'`
kill -9 `ps ax|grep redis|grep server|awk '{print $1}'`
