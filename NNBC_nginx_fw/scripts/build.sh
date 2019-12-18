#!/bin/bash

cd /NNBC
make
make install
ldconfig /usr/local/lib

cd /nginx_source
./configure --prefix=/usr/local/nginx-nnbc/ --add-module=/NNBC_nginx_fw/nginx_nnbc_http_module/ --with-http_ssl_module
make
make install

cp /NNBC_nginx_fw/conf/nginx.conf /usr/local/nginx-nnbc/conf/nginx.conf
