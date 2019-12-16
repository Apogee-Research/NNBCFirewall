FROM ubuntu:bionic
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y \
    build-essential libpcre3-dev zlib1g-dev libcurl4-openssl-dev \
    postgresql-10 redis-server libhiredis-dev libyaml-dev \
    libssl-dev libpq-dev wget net-tools python3-pip
RUN python3 -m pip install pyyaml psycopg2 psycopg2-binary redis numpy matplotlib

RUN sed -E -i "s/local(.*)all(.*)all(.*)peer/local\1all\2all\3md5/" /etc/postgresql/10/main/pg_hba.conf
USER postgres
RUN /etc/init.d/postgresql start \
 && createuser nnbc_user \
 && createdb nnbcdb --owner nnbc_user \
 && psql -c "ALTER ROLE nnbc_user WITH PASSWORD 'nnbc_pass'" \
 && /etc/init.d/postgresql stop
USER root

RUN wget -q http://nginx.org/download/nginx-1.14.2.tar.gz \
 && tar xf nginx-1.14.2.tar.gz \
 && rm nginx-1.14.2.tar.gz \
 && mv nginx-1.14.2 nginx_source

COPY NNBC NNBC
COPY NNBC_nginx_fw NNBC_nginx_fw

RUN NNBC_nginx_fw/scripts/build.sh

CMD NNBC_nginx_fw/scripts/run.sh
