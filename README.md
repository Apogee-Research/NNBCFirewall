# The NNBC DDoS Firewall

The NNBC DDoS Firewall is an nginx module that protects a web site
against application-level DDoS attacks. If one integrates the firewall
with a network overlay provider that offers a blacklist API (e.g.,
Akamai), this firewall will also defend against volumetric bandwidth
attacks (attacks exhaust network bandwidth even though the server is
not processing the attackers' requests).

## License

Please see the file LICENSE that accompanied this distribution.

## Installation

See the Configuration section below for configuring the firewall.

### Docker

*Note: This example assumes a Linux host. Docker networking in Windows requires some extra steps.*

* build the nnbc image
```
docker build -t nnbc .
```

* optional: start a dockerized nginx server listening to port 8000
```
docker run --name server -d --rm -p 8000:80 nginx
```

* start the nnbc container
```
docker run --network host --rm -d --name nnbc nnbc
```

Webserver should now be on your localhost, accessible directly at port 8000 or via NNBC at port 80.

* cleanup
```
docker kill nnbc server
```

### Bare Metal

If on Ubuntu or other Debian Linux host:
```
cd NNBC_NGINX_fw
scripts/install.sh BASE setup
scripts/install.sh BASE rebuild
```

## Configuration

There are four critical elements of configuration:

1. Specifying the location of the server being protected.

2. Specifying the URL to be used by the sensor.

3. Creating the whitelist of hosts that can always access the
server. The sensor should be on that list.

4. Creating the list of legitimate proxies. When a client connects via
a proxy, the firewall will use the X-Forwarded-For header (or an
alternate header) to identify the client. If the connection is not
from an IP address on the proxy list, the X-Forwarded-For header is
ignored.

### Configuring the Server Location

The NNBC firewall uses the nginx proxy configuration.
Thus, one can see the nginx documentation for how to
specify the server locaion. That said, in short,
one edits /usr/local/nginx-nnbc/conf/nginx.conf and
specifies the "proxy_pass" configuration item. See
NNBC_nginx_fw/conf/nginx.conf for an example.

### Configuring the Sensor URL

Edit /etc/nnbc/nnbc_conf.yaml, modifying the "sensor_cmd" paramenter
to specify the sensor command. The example in NNBC/conf/nnbc_conf.yaml
runs the command wget, passing a URL that accesses the root of the web
server. It also uses the "sensor_poll" parameter to specify that the
URL should be accessed once every two seconds.

### Creating the Whitelist

Edit /etc/nnbc/nnbc_conf.yaml, modifying the "whitelist" parameter.
The whitelist is a string--it must start and end with quotation
marks. The string itself is a comma-separated series of network
addresses in the form "a.b.c.d/#", e.g., "10.10.0.0/16". The sensor
should be on the white list.

### Creating the Proxy List

If there is a web proxy, all requests will appear to come from the
same address. Specifying the proxy servers tells the NNBC which hosts
to honor the "X-Forwarded-For" field--the field is ignored if the
request comes from a host that is not in the proxy list. The format
of the proxy list is the same as that of the white list.

If the proxies use a field other than X-Forwarded-For, the field name
is specified in the nginx.conf file.

### Other Configuration Items

This package comes with several skeleton configuration files for nginx
and for the NNBC. Both contain comments that will assist the user.

### Experimental Code

In the file NNBC_nginx_fw/nginx_nnbc_http_module/ngx_nnbc_http_module.c,
there is a comment that begins "This is experimental code." Below the comment
is commented-out code. If one removes the comments, then any http or https
request that gets a four-hundred-series response code causes a misbehave
invocation against the caller. This will cause a client that repeated types
the wrong password or repeatedly queries a non-existent URL to (eventually)
be blocked from the server. This is a useful feature, but use at your own peril.
It is not heavily tested.

### Distribution Statement
Distribution Statement "A" (Approved for Public Release, Distribution Unlimited)
