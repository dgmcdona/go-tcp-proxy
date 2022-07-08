# tcp-proxy

A small TCP proxy written in Go

This project was intended for debugging text-based protocols. The next version will address binary protocols.


## Usage

```
$ tcp-proxy --help
Usage of tcp-proxy:
Usage of out/tcp-proxy:
  -c	output ansi colors
  -config string
    	path to YAML config file containing filter rules, one per line
  -h	output hex
  -l string
    	local address (default ":9999")
  -match string
    	match regex (in the form 'regex')
  -n	disable nagles algorithm
  -r string
    	remote address (default "localhost:80")
  -replace string
    	replace regex (in the form 'regex~replacer')
  -unwrap-tls
    	remote connection with TLS exposed unencrypted locally
  -v	display server actions
  -vv
    	display server actions and all tcp data
  -yara string
    	path to file containing yara rules for connection blocking/logging
```

*Note: Regex match and replace*
**only works on text strings**
*and does NOT work across packet boundaries*

### Simple Example

Since HTTP runs over TCP, we can also use `tcp-proxy` as a primitive HTTP proxy:

```
$ tcp-proxy -r echo.jpillora.com:80
Proxying from localhost:9999 to echo.jpillora.com:80
```

Then test with `curl`:

```
$ curl -H 'Host: echo.jpillora.com' localhost:9999/foo
{
  "method": "GET",
  "url": "/foo"
  ...
}
```

### Match Example

```
$ tcp-proxy -r echo.jpillora.com:80 -match 'Host: (.+)'
Proxying from localhost:9999 to echo.jpillora.com:80
Matching Host: (.+)

#run curl again...

Connection #001 Match #1: Host: echo.jpillora.com
```

### Replace Example

```
$ tcp-proxy -r echo.jpillora.com:80 -replace '"ip": "([^"]+)"~"ip": "REDACTED"'
Proxying from localhost:9999 to echo.jpillora.com:80
Replacing "ip": "([^"]+)" with "ip": "REDACTED"
```

```
#run curl again...
{
  "ip": "REDACTED",
  ...
```

*Note: The `-replace` option is in the form `regex~replacer`. Where `replacer` may contain `$N` to substitute in group `N`.*

### Yara example

A file containing yara rules can be provided for each connection. Rules that are
prefixed with `log_` will generate a log message upon matches but allow the
connection to continue. All other rule matches will cause the connection to be
dropped.

### Building from docker container

In order to produce a static binary while using `cgo` and the `libyara` library,
a dockerfile has been included which will compile the file and export it to the
`out` directory when the following command has run:
```
sudo DOCKER_BUILDKIT=1 docker build --target export -t test . --output out
```

### Todo

* Implement `tcpproxy.Conn` which provides accounting and hooks into the underlying `net.Conn`
* Verify wire protocols by providing `encoding.BinaryUnmarshaler` to a `tcpproxy.Conn`
* Modify wire protocols by also providing a map function
* Implement [SOCKS v5](https://www.ietf.org/rfc/rfc1928.txt) to allow for user-decided remote addresses
