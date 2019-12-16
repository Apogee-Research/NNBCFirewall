#!/bin/bash

set -e

/etc/init.d/postgresql start
/usr/bin/redis-server --daemonize yes
/NNBC/src/reset_db.py /etc/nnbc/nnbc_conf.yaml
/NNBC/src/nnbc.py /etc/nnbc/nnbc_conf.yaml &
/usr/local/nginx-nnbc/sbin/nginx


while `sleep 3`; do
  if ! kill -0 `cat /usr/local/nginx-nnbc/logs/nginx.pid`; then
    /usr/local/nginx-nnbc/sbin/nginx
  fi
done
