#!/bin/bash


cd `dirname $0`/..
NGINX_VERSION=`head -1 NGINX_VERSION`
if [[ -d nginx-${NGINX_VERSION} ]]; then
  # nginx is already downloaded
  exit 0
fi

if ! wget http://kamino.apogee-research.com/gfrazier/artifacts/nginx-${NGINX_VERSION}.tar.gz >& /dev/null; then
  if ! wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz ; then
    echo "Failed to download nginx from either kamino or nginx.org."
    exit -1
  else
    echo "Downloaded nginx-${NGINX_VERSION} from nginx.org."
  fi
else
  echo "Downloaded nginx-${NGINX_VERSION} from kamino."
fi

tar xf nginx-${NGINX_VERSION}.tar.gz
