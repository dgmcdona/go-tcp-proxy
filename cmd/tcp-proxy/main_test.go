package main

import (
	"testing"

	proxy "github.com/jpillora/go-tcp-proxy"
)

var configValid = `
- type: substring
  find: foo
  replace: bar
- type: regex
  pattern: "[a-f0-9]{4}"
  replace: 1337
- type: bytes
  findbytes: [0x11, 0x22, 0x33, 0x44]
  replacebytes: [0x55, 0x66, 0x77, 0x88]
`

func TestConfigParse(t *testing.T) {
	p := new(proxy.Proxy)

	if err := readConfigData(p, []byte(configValid)); err != nil {
		t.Errorf("failed to parse valid config: %v", err)
	}

	for _, f := range p.Replacers {
		t.Logf("replacer type: %T", f)
		if br, ok := f.(*proxy.BytesReplacer); ok {
			t.Log(br.In)
			t.Log(br.Out)
		}
	}
}
