package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
)

// Proxy - Manages a Proxy connection, piping data between local and remote.
type Proxy struct {
	sentBytes     uint64
	receivedBytes uint64
	laddr, raddr  *net.TCPAddr
	lconn, rconn  io.ReadWriteCloser
	erred         bool
	errsig        chan bool
	tlsUnwrapp    bool
	tlsAddress    string

	Matcher   func([]byte)
	Replacers []Replacer

	// Settings
	Nagles    bool
	Log       Logger
	OutputHex bool
}

// New - Create a new Proxy instance. Takes over local connection passed in,
// and closes it when finished.
func New(lconn *net.TCPConn, laddr, raddr *net.TCPAddr) *Proxy {
	return &Proxy{
		lconn:  lconn,
		laddr:  laddr,
		raddr:  raddr,
		erred:  false,
		errsig: make(chan bool),
		Log:    NullLogger{},
	}
}

// NewTLSUnwrapped - Create a new Proxy instance with a remote TLS server for
// which we want to unwrap the TLS to be able to connect without encryption
// locally
func NewTLSUnwrapped(lconn *net.TCPConn, laddr, raddr *net.TCPAddr, addr string) *Proxy {
	p := New(lconn, laddr, raddr)
	p.tlsUnwrapp = true
	p.tlsAddress = addr
	return p
}

type setNoDelayer interface {
	SetNoDelay(bool) error
}

// Start - open connection to remote and start proxying data.
func (p *Proxy) Start() {
	defer p.lconn.Close()

	var err error
	//connect to remote
	if p.tlsUnwrapp {
		p.rconn, err = tls.Dial("tcp", p.tlsAddress, nil)
	} else {
		p.rconn, err = net.DialTCP("tcp", nil, p.raddr)
	}
	if err != nil {
		p.Log.Warn("Remote connection failed: %s", err)
		return
	}
	defer p.rconn.Close()

	//nagles?
	if p.Nagles {
		if conn, ok := p.lconn.(setNoDelayer); ok {
			conn.SetNoDelay(true)
		}
		if conn, ok := p.rconn.(setNoDelayer); ok {
			conn.SetNoDelay(true)
		}
	}

	//display both ends
	p.Log.Info("Opened %s >>> %s", p.laddr.String(), p.raddr.String())

	//bidirectional copy
	go p.pipe(p.lconn, p.rconn)
	go p.pipe(p.rconn, p.lconn)

	//wait for close...
	<-p.errsig
	p.Log.Info("Closed (%d bytes sent, %d bytes recieved)", p.sentBytes, p.receivedBytes)
}

func (p *Proxy) err(s string, err error) {
	if p.erred {
		return
	}
	if err != io.EOF {
		p.Log.Warn(s, err)
	}
	p.errsig <- true
	p.erred = true
}

func (p *Proxy) pipe(src, dst io.ReadWriter) {
	islocal := src == p.lconn

	var dataDirection string
	if islocal {
		dataDirection = ">>> %d bytes sent%s"
	} else {
		dataDirection = "<<< %d bytes recieved%s"
	}

	var byteFormat string
	if p.OutputHex {
		byteFormat = "%x"
	} else {
		byteFormat = "%s"
	}

	//directional copy (64k buffer)
	buff := make([]byte, 0xffff)
	for {
		n, err := src.Read(buff)
		if err != nil {
			p.err("Read failed '%s'\n", err)
			return
		}
		b := buff[:n]

		//execute match
		if p.Matcher != nil {
			p.Matcher(b)
		}

		//execute replace
		for _, replacer := range p.Replacers {
			b = replacer.Replace(b)
		}

		//show output
		p.Log.Debug(dataDirection, n, "")
		p.Log.Trace(byteFormat, b)

		//write out result
		n, err = dst.Write(b)
		if err != nil {
			p.err("Write failed '%s'\n", err)
			return
		}
		if islocal {
			p.sentBytes += uint64(n)
		} else {
			p.receivedBytes += uint64(n)
		}
	}
}

type Replacer interface {
	Replace([]byte) []byte
}

type ReplacerConfig struct {
	ReplacerType      string `yaml:"type"`
	SubString         string `yaml:"find"`
	ReplacementString string `yaml:"replace"`
	SearchBytes       []byte `yaml:"findbytes"`
	ReplacementBytes  []byte `yaml:"replacebytes"`
	Pattern           string `yaml:"pattern"`
}

type StringReplacer struct {
	in  string
	out string
}

type RegexReplacer struct {
	Pattern     regexp.Regexp
	Replacement string
}

type BytesReplacer struct {
	In  []byte
	Out []byte
}

func (br *BytesReplacer) Replace(src []byte) []byte {
	return bytes.ReplaceAll(src, br.In, br.Out)
}

func (rr *RegexReplacer) Replace(in []byte) []byte {
	return rr.Pattern.ReplaceAll(in, []byte(rr.Replacement))
}

func (sr *StringReplacer) Replace(in []byte) []byte {
	sNew := strings.ReplaceAll(string(in), sr.in, sr.out)
	return []byte(sNew)
}

func (r ReplacerConfig) Parse() (Replacer, error) {
	switch r.ReplacerType {
	case "substring":
		if r.SubString == "" {
			return nil, fmt.Errorf("no substring provided")
		}
		return &StringReplacer{r.SubString, r.ReplacementString}, nil
	case "regex":
		if r.Pattern == "" {
			return nil, fmt.Errorf("regex pattern empty")
		}
		pattern, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex: %w", err)
		}
		return &RegexReplacer{*pattern, r.ReplacementString}, nil
	case "bytes":
		if len(r.SearchBytes) == 0 {
			return nil, fmt.Errorf("no search bytes provided")
		}
		return &BytesReplacer{r.SearchBytes, r.ReplacementBytes}, nil
	default:
		return nil, fmt.Errorf("unsupported replacer type: <%s>", r.ReplacerType)
	}
}
