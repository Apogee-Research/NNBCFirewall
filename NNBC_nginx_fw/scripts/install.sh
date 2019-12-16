#!/bin/bash

BASEDIR=$(realpath $(dirname $0)/..)
cd $BASEDIR
NGINX_V=$(head -1 NGINX_VERSION)
PREFIX=/usr/local/nginx-nnbc
NNBC_PID=$PREFIX/logs/nnbc.pid
SAVEDIR=/tmp/nnbc_saved_logs
# the following files are collected in $SAVEDIR
#   nnbc_gnuplot.dat nnbc.log nnbc_clients_table.txt

function setup {
  sudo apt-get update
  sudo apt-get install -y build-essential libpcre3-dev zlib1g-dev libcurl4-openssl-dev \
      redis-server libhiredis-dev python python-pip python3 python3-pip libyaml-dev \
      postgresql-10 postgresql-server-dev-all libssl-dev
  sudo pip install uwsgi redis
  sudo pip3 install psycopg2 psycopg2-binary redis edgegrid-python numpy matplotlib
  ./scripts/get_nginx.sh
  # configure postgres, as the default installation doesn't work for our needs
  # (change to password authentication, allow remote connections)
  sudo systemctl stop postgresql
  sudo cp conf/postgresql.conf /etc/postgresql/10/main/
  sudo cp conf/pg_hba.conf /etc/postgresql/10/main/
  sudo systemctl start postgresql
  if ! sudo -u postgres psql -c "\du" | grep -q nnbc_user; then
    sudo -u postgres createuser nnbc_user
    sudo -u postgres createdb nnbcdb --owner nnbc_user
    sudo -u postgres psql -c "ALTER ROLE nnbc_user WITH PASSWORD 'nnbc_pass'"
  fi
}

function stop {
  rm -rf $SAVEDIR
  mkdir $SAVEDIR

  sudo -u postgres psql nnbcdb -c "SELECT * FROM nnbc_clients;" &> $SAVEDIR/nnbc_clients_table.txt || echo Postgres dump failed

  sudo systemctl stop nginx-nnbc || echo stop nginx-nnbc failed
  sudo systemctl stop nnbc-sensor || echo stop nnbc-sensor failed
  if [[ -f $NNBC_PID ]]; then
    kill $(cat $NNBC_PID) || echo "kill NNBC failed"
    sudo rm $NNBC_PID
  fi
  sudo systemctl stop postgresql

  local savefiles=( /tmp/nnbc_gnuplot.dat /tmp/nnbc.log $PREFIX/logs/access.log $PREFIX/logs/error.log )
  for f in "${savefiles[@]}"; do
    if [[ -f $f ]]; then
      sudo mv $f $SAVEDIR/
    fi
  done
}

function build {
  pushd ../PubSubStub/c
  PUBSUB_PKG=redis make
  sudo PUBSUB_PKG=redis make install
  popd

  pushd ../NNBC
  make
  sudo NNBC_CONF_FILE=$NNBC_CONF_FILE make install
  popd

  sudo ldconfig

  pushd nginx-${NGINX_V}
  ./configure --prefix=$PREFIX --add-module=../nginx_nnbc_http_module --with-http_ssl_module
  sudo ldconfig /usr/local/bin
  make
  sudo make install
  popd

  sudo cp conf/$NGX_CONF_FILE $PREFIX/conf/nginx.conf
  sudo cp conf/nginx-nnbc.service /lib/systemd/system/
  sudo cp conf/nnbc-sensor.service /lib/systemd/system/
  sudo systemctl daemon-reload
}

function start {
  sudo systemctl start postgresql
  /usr/local/bin/nnbc/reset_db.py /etc/nnbc/nnbc_conf.yaml
  echo $! | sudo tee $NNBC_PID
  sudo systemctl start nginx-nnbc
  sudo systemctl start nnbc-sensor
}


export NNBC_CONF_FILE=nnbc_conf.yaml
export NGX_CONF_FILE=nginx.conf

case "$1" in
  setup)  # only run initially and when dependencies change
    setup
    ;;
  stop)
    stop
    ;;
  start)
    start
    ;;
  restart)
    stop
    start
    ;;
  build)  # use this is build for the first time, too
    stop
    build
    start
    ;;
  *)
    echo "Specify one of:"
    echo "  \"setup\"   -- installs necessary packages and performs some preconfig. Must be run first."
    echo "  \"build\"   -- does a stop and then (re-)compiles the firewall."
    echo "  \"stop\"    -- stop the firewall and dump the NNBC database."
    echo "  \"start\"   -- start the firewall services (postgres, nginx, and the sensor)."
    echo "  \"restart\" -- stop and start."
    echo "  \"build\" (which does a stop first)"
    ;;
esac
