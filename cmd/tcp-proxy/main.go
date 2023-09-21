package main

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/pflag"
	proxy "gitlab.cs.uno.edu/dgmcdona/go-tcp-proxy"
)

var (
	version = "0.0.0-src"
	connid  = uint64(0)

	localAddr  = pflag.StringP("local-address", "l", ":9999", "local address")
	remoteAddr = pflag.StringP("remote-address", "r", "localhost:80", "remote address")
	verbose    = pflag.CountP("verbose", "v", "verbose logging")
	nagles     = pflag.BoolP("nagles", "n", false, "disable nagles algorithm")
	hex        = pflag.BoolP("hex", "h", false, "output hex")
	help       = pflag.Bool("help", false, "output hex")
	colors     = pflag.BoolP("colors", "c", false, "output ansi colors")
	unwrapTLS  = pflag.BoolP("unwrap-tls", "u", false, "remote connection with TLS exposed unencrypted locally")
	yaraConfig = pflag.StringP("yara", "y", "", "path to file containing yara rules for connection blocking")
)

func main() {
	pflag.Parse()

	if *help {
		pflag.Usage()
		return
	}

	logger := proxy.ColorLogger{
		Level: *verbose,
		Color: *colors,
	}

	logger.Info("go-tcp-proxy (%s) proxying from %v to %v ", version, *localAddr, *remoteAddr)

	laddr, err := net.ResolveTCPAddr("tcp", *localAddr)
	if err != nil {
		logger.Warn("Failed to resolve local address: %s", err)
		os.Exit(1)
	}
	raddr, err := net.ResolveTCPAddr("tcp", *remoteAddr)
	if err != nil {
		logger.Warn("Failed to resolve remote address: %s", err)
		os.Exit(1)
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		logger.Warn("Failed to open local port to listen: %s", err)
		os.Exit(1)
	}

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			logger.Warn("Failed to accept connection '%s'", err)
			continue
		}
		connid++

		var p *proxy.Proxy
		if *unwrapTLS {
			logger.Info("Unwrapping TLS")
			p = proxy.NewTLSUnwrapped(conn, laddr, raddr, *remoteAddr)
		} else {
			p = proxy.New(conn, laddr, raddr)
		}

		p.Log = proxy.ColorLogger{
			Level:  *verbose,
			Prefix: fmt.Sprintf("Connection #%03d ", connid),
			Color:  *colors,
		}

		if *yaraConfig != "" {
			if err := p.LoadYaraConfig(*yaraConfig); err != nil {
				logger.Warn("error loading yara config: %v", err)
			}
		}

		p.Nagles = *nagles
		p.OutputHex = *hex

		go p.Start()
	}
}
