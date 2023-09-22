# tcp-proxy

A small TCP proxy written in Go

This project was forked from https://github.com/jpillora/go-tcp-proxy, which was originally designed for working with text-based protocols. We have redesigned it to support filtering and replacement through yara rules. It works as a simple TCP proxy, with an option to scan each TCP packet with one or more yara rules.

## Usage

```
Usage of ./tcp-proxy:
  -c, --colors                  output ansi colors
      --help                    output hex
  -h, --hex                     output hex
  -l, --local-address string    local address (default ":9999")
  -n, --nagles                  disable nagles algorithm
  -r, --remote-address string   remote address (default "localhost:80")
  -u, --unwrap-tls              remote connection with TLS exposed unencrypted locally
  -v, --verbose count           verbose logging
  -y, --yara string             path to file containing yara rules for connection blocking

```

 If you want a connection to be dropped on a yara rule match, add a `drop` tag to that rule. If you want a connection to be logged on a yara rule match, include either the `log` or `warn` tags.

For example, the following rule issues a warning message and terminates the connection if the rule matches TCP packet data:
```yara
rule FooRule: warn drop
{
    strings:
        $my_text_string = "foo"
        $my_hex_string = { E2 34 A1 C8 23 FB }

    condition:
        $my_text_string or $my_hex_string
}
```

You can replace matching bytes by specifying a `sub` rule metadata item, with either text, or bytes in the usual yara syntax. For example, the following rule replaces a string match of "bar" with four `\x41` (ascii 'A') characters:

```yara
rule BarRule: warn
{
    meta:
        sub = "{ 41 41 41 41 }"

    strings:
        $a = "bar"

    condition:
        $a
}
```

*does NOT work across packet boundaries*

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
