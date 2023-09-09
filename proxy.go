package proxy

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	yara "github.com/hillu/go-yara/v4"
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

	scannerLock sync.Mutex
	Scanner     *yara.Scanner
	Watcher     *fsnotify.Watcher

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
	// connect to remote
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

	// nagles?
	if p.Nagles {
		if conn, ok := p.lconn.(setNoDelayer); ok {
			conn.SetNoDelay(true)
		}
		if conn, ok := p.rconn.(setNoDelayer); ok {
			conn.SetNoDelay(true)
		}
	}

	// display both ends
	p.Log.Info("Opened %s >>> %s", p.laddr.String(), p.raddr.String())

	// bidirectional copy
	if p.Scanner != nil && p.Watcher != nil {
		go p.watchYaraFile()
	}
	go p.pipe(p.lconn, p.rconn)
	go p.pipe(p.rconn, p.lconn)

	// wait for close...
	<-p.errsig
	p.Log.Info("Closed (%d bytes sent, %d bytes recieved)", p.sentBytes, p.receivedBytes)
}

func (p *Proxy) watchYaraFile() {
	for {
		evt := <-p.Watcher.Events
		if !evt.Has(fsnotify.Write) {
			continue
		}
		p.rebuildScanner()
	}
}

func (p *Proxy) rebuildScanner() {
	p.Log.Info("rulefile updated")
	p.scannerLock.Lock()
	defer p.scannerLock.Unlock()

	path := p.Watcher.WatchList()[0]
	r, err := os.Open(path)
	if err != nil {
		p.Log.Warn("failed to open yara rule file %s: %v", path, err)
		return
	}
	rules, err := yara.ReadRules(r)
	if err != nil {
		p.Log.Warn("error reading yara rules in file %s: %v", path, err)
		return
	}
	scanner, err := yara.NewScanner(rules)
	if err != nil {
		p.Log.Warn("failed to compile yara scanner for rules from file %s: %v", path, err)
		return
	}
	p.Scanner = scanner
}

func (p *Proxy) RuleMatching(ctx *yara.ScanContext, rule *yara.Rule) (bool, error) {
	tags := rule.Tags()
	for _, tag := range tags {
		id := rule.Identifier()
		if strings.ToLower(tag) == "log" {
			p.Log.Info("match found for rule %s", id)
		}
		if strings.ToLower(tag) == "warn" {
			p.Log.Warn("match found for rule %s", id)
		}
		if strings.ToLower(tag) == "drop" {
			p.err("dropping connection", fmt.Errorf("match on rule %s", id))
		}
	}

	sub_value, ok := p.getSubstitution(rule.Metas())
	for _, s := range rule.Strings() {
	}
	return false, nil
}

func (p *Proxy) getSubstitution(metas []yara.Meta) ([]byte, bool) {
	var replacement []byte
	var err error
	meta_map := map[string]interface{}{}
	for _, meta := range metas {
		if strings.ToLower(meta.Identifier) != "sub" {
			continue
		}
		mvs, ok := meta.Value.(string)
		if !ok {
			p.Log.Warn("substitution metadata value should be a string")
			continue
		}
		if strings.HasPrefix(mvs, "{ ") && strings.HasSuffix(mvs, " }") {
			bts_raw := strings.TrimRight(strings.TrimLeft(mvs, " {"), "} ")
			bts := strings.ReplaceAll(bts_raw, " ", "")
			replacement, err = hex.DecodeString(bts)
			if err != nil {
				p.Log.Warn("failed to parse substitution value as yara hex bytes")
				continue
			}
			return replacement, true
		} // else if
	}
	return nil, false
}

func (p *Proxy) err(s string, err error) {
	if p.erred {
		return
	}
	if err != io.EOF {
		p.Log.Warn(s, err.Error())
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

	// directional copy (64k buffer)
	buff := make([]byte, 0xffff)
	for {
		n, err := src.Read(buff)
		if err != nil {
			p.err("Read failed '%s'\n", err)
			return
		}
		b := buff[:n]

		if p.Scanner != nil && islocal {
			p.scannerLock.Lock()
			p.Scanner.ScanMem(b)
			p.scannerLock.Unlock()
		}

		// show output
		p.Log.Debug(dataDirection, n, "")
		p.Log.Trace(byteFormat, b)

		// write out result
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
		return fmt.Errorf("failed to get yara rules: %w", err)
	}
	p.Scanner, err = yara.NewScanner(rules)
	if err != nil {
		p.Scanner = nil
		return fmt.Errorf("failed to create new yara scanner: %w", err)
	}
	p.Scanner.SetCallback(p)

	p.Watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher for yara rules file: %w", err)
	}
	err = p.Watcher.Add(filePath)
	if err != nil {
		return fmt.Errorf("failed to add file %s to file watcher: %w", filePath, err)
	}
	return nil
}
