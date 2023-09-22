package proxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	yara "github.com/hillu/go-yara/v4"
)

var scanners sync.Map

var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0xffff)
	},
}

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
	Scanner   *yara.Scanner
	Bell      bool

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

func (p *Proxy) RuleMatching(ctx *yara.ScanContext, rule *yara.Rule) (bool, error) {
	ruleID := rule.Identifier()
	p.Log.Warn("Rule %s matched", ruleID)
	for _, s := range rule.Strings() {
		matches := s.Matches(ctx)
		for _, m := range matches {
			p.Log.Warn("%s: %s", s.Identifier(), string(m.Data()))
		}
	}

	if strings.HasPrefix(ruleID, "log_") {
		if p.Bell {
			fmt.Print("\a")
		}
		return true, nil
	}
	p.err("connection terminated due to rule match on rule %s", errors.New(ruleID))
	return false, nil
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
	buff := bufPool.Get().([]byte)
	defer bufPool.Put(buff)

	for {
		if p.erred {
			break
		}
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

		if p.Scanner != nil && islocal {
			p.Scanner.ScanMem(b)
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

func (p *Proxy) LoadYaraConfig(filePath string) error {
	fi, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat yara config: %v", err)
	}
	if iScanner, ok := scanners.Load(fi.ModTime()); ok {
		scanner, _ := iScanner.(yara.Scanner)
		p.Scanner = &scanner
		p.Scanner.SetCallback(p)
		return nil
	}

	configChange := "modified"
	if fi.ModTime().IsZero() {
		configChange = "created"
	}
	p.Log.Info("yara rules file %s - compiling", configChange)

	cmp, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("error creating yara compiler: %v", err)
	}
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open yara config file: %v", err)
	}
	defer f.Close()
	if err := cmp.AddFile(f, "proxy"); err != nil {
		return fmt.Errorf("error adding file to compiler: %v", err)
	}
	rules, err := cmp.GetRules()
	if err != nil {
		return fmt.Errorf("failed to get yara rules: %v", err)
	}
	scanner, err := yara.NewScanner(rules)
	if err != nil {
		return fmt.Errorf("failed to create new yara scanner: %v", err)
	}
	p.Scanner = scanner
	scanners.Range(func(key interface{}, value interface{}) bool {
		scanners.Delete(key)
		return true
	})
	scanners.Store(fi.ModTime(), *scanner)
	p.Scanner.SetCallback(p)
	return nil
}
