package proxy

import (
	"bytes"
	"testing"

	"gopkg.in/yaml.v3"
)

var configValid = `
- type: substring
  find: "foo"
  replace: "bar"
- type: regex
  find: "[a-f0-9]{4}"
  replace: "1337"
- type: bytes
  find: [0x11, 0x22, 0x33, 0x44]
  replace: [0x55, 0x66, 0x77, 0x88]
`

var sliceLen = 4

var invalidConfigs = []string{
	`
- type: string
  replace: bar
`,
	`
- type: regex
  replace: bar
`,
	`
- type: bytes
  replacebytes: [0x00]
`,
}

func TestConfigParse(t *testing.T) {
	var p Proxy
	p.Log = NullLogger{}

	if err := p.LoadConfig([]byte(configValid)); err != nil {
		t.Errorf("failed to parse valid config: %v", err)
	}

	for _, f := range p.Replacers {
		if s, ok := f.(*BytesReplacer); ok {
			if len(s.In) != sliceLen {
				t.Errorf("slice too big: wanted %d elements, got %d", sliceLen, len(s.In))
			}
		}
		t.Log(f.String())
	}

	for _, ic := range invalidConfigs {
		err := p.LoadConfig([]byte(ic))
		if err == nil {
			t.Errorf("error should have been returned on invalid config parse")
		}
		// t.Log(err.Error())
	}
}

func TestYamlRead(t *testing.T) {
	var r []ReplacerConfig

	err := yaml.Unmarshal([]byte(configValid), &r)
	if err != nil {
		t.Errorf("error reading config: %v", err)
	}

	for _, repl := range r {

		if repl.ReplacerType == "bytes" {
			f, ok := repl.Find.([]interface{})
			if !ok {
				t.Errorf("unexpected type: wanted slice, got %T", repl.Find)
			}

			if len(f) != sliceLen {
				t.Errorf("unexpected element count: wanted %d, got %d",
					sliceLen, len(f))
			}
		}
	}

}

func TestReplaceByte(t *testing.T) {
	br := &BytesReplacer{
		[]byte{0x31, 0x33, 0x33, 0x37},
		[]byte{0x62, 0x65, 0x65, 0x66},
	}

	in := "I am 1337"
	out := "I am beef"
	replaced := br.Replace([]byte(in))
	if !bytes.Equal([]byte(out), replaced) {
		t.Errorf("failed to replace bytes correctly: wanted %s, got %s", out, string(replaced))
	}
	t.Log(string(replaced))
}
