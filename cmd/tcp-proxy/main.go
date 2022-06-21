package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	yara "github.com/hillu/go-yara/v4"
	proxy "gitlab.cs.uno.edu/dgmcdona/go-tcp-proxy"
)

var (
	version = "0.0.0-src"
	matchid = uint64(0)
	connid  = uint64(0)
	logger  proxy.ColorLogger

	localAddr   = flag.String("l", ":9999", "local address")
	remoteAddr  = flag.String("r", "localhost:80", "remote address")
	verbose     = flag.Bool("v", false, "display server actions")
	veryverbose = flag.Bool("vv", false, "display server actions and all tcp data")
	nagles      = flag.Bool("n", false, "disable nagles algorithm")
	hex         = flag.Bool("h", false, "output hex")
	colors      = flag.Bool("c", false, "output ansi colors")
	unwrapTLS   = flag.Bool("unwrap-tls", false, "remote connection with TLS exposed unencrypted locally")
	match       = flag.String("match", "", "match regex (in the form 'regex')")
	replace     = flag.String("replace", "", "replace regex (in the form 'regex~replacer')")
	config      = flag.String("config", "", "path to config file containing filter rules, one per line")
	yaraConfig  = flag.String("yara", "", "path to file containing yara rules for connection blocking")
)

func main() {
	flag.Parse()

	logger := proxy.ColorLogger{
		Verbose: *verbose,
		Color:   *colors,
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

	matcher := createMatcher(*match)
	replacer, err := createReplacer(*replace)
	if err != nil && err != io.ErrUnexpectedEOF {
		logger.Warn(err.Error())
	}

	if *veryverbose {
		*verbose = true
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
			Verbose:     *verbose,
			VeryVerbose: *veryverbose,
			Prefix:      fmt.Sprintf("Connection #%03d ", connid),
			Color:       *colors,
		}

		p.Matcher = matcher

		if *config != "" {
			f, err := os.Open(*config)
			if err != nil {
				logger.Warn("failed to read config: %v", err)
				goto SKIPCONFIG
			}
			defer f.Close()

			config, err := io.ReadAll(f)
			if err != nil {
				logger.Warn("error reading config data: %v", err)
				goto SKIPCONFIG
			}
			if err := p.LoadConfig(config); err != nil {
				logger.Warn("error loading config: %v", err)
			}

		}
	SKIPCONFIG:
		if *yaraConfig != "" {
			rules, err := yara.LoadRules(*yaraConfig)
			if err != nil {
				logger.Warn("failed to get yara rules: %v", err)
				goto SKIPYARA
			}
			p.Scanner, err = yara.NewScanner(rules)
			if err != nil {
				logger.Warn("failed to create new yara scanner: %v", err)
				p.Scanner = nil
			}
		}
	SKIPYARA:

		if replacer != nil {
			p.Replacers = append(p.Replacers, replacer)
		}

		p.Nagles = *nagles
		p.OutputHex = *hex

		go p.Start()
	}
}

func createMatcher(match string) func([]byte) {
	if match == "" {
		return nil
	}
	re, err := regexp.Compile(match)
	if err != nil {
		logger.Warn("Invalid match regex: %s", err)
		return nil
	}

	logger.Info("Matching %s", re.String())
	return func(input []byte) {
		ms := re.FindAll(input, -1)
		for _, m := range ms {
			matchid++
			logger.Info("Match #%d: %s", matchid, string(m))
		}
	}
}

func createReplacer(replace string) (proxy.Replacer, error) {
	if replace == "" {
		return nil, io.ErrUnexpectedEOF
	}
	//split by / (TODO: allow slash escapes)
	parts := strings.Split(replace, "~")
	if len(parts) != 2 {
		logger.Warn("Invalid replace option")
		return nil, fmt.Errorf("invalid replace option")
	}

	re, err := regexp.Compile(string(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid replace regex: %s", err)
	}

	repl := []byte(parts[1])

	logger.Info("Replacing %s with %s", re.String(), repl)
	return &proxy.RegexReplacer{
		Pattern:     *re,
		Replacement: string(repl)}, nil
}
