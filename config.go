package proxy

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/go-multierror"
	"gopkg.in/yaml.v3"
)

type Replacer interface {
	Replace([]byte) []byte
	fmt.Stringer
}

type ReplacerConfig struct {
	ReplacerType string      `yaml:"type"`
	Find         interface{} `yaml:"find"`
	Replace      interface{} `yaml:"replace"`
}

type StringReplacer struct {
	in  string
	out string
}

func (sr *StringReplacer) String() string {
	return fmt.Sprintf("StringReplacer: Find: %s, Replace: %s",
		sr.in, sr.out)
}

type RegexReplacer struct {
	Pattern     regexp.Regexp
	Replacement string
}

func (rr *RegexReplacer) String() string {
	return fmt.Sprintf("RegexReplacer: Pattern: %s, Replace: %s",
		rr.Pattern.String(), rr.Replacement)
}

type BytesReplacer struct {
	In  []byte
	Out []byte
}

func (br *BytesReplacer) String() string {
	return fmt.Sprintf("BytesReplacer: Find: %v, Replace: %v",
		br.In, br.Out)
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
	case "substring", "str", "string", "ss", "substr":

		findStr, ok := r.Find.(string)
		if !ok || findStr == "" {
			return nil, fmt.Errorf("no substring provided")
		}
		replStr, ok := r.Replace.(string)
		if !ok {
			return nil, fmt.Errorf("replacement not of type string")
		}

		return &StringReplacer{findStr, replStr}, nil
	case "regex", "regexp", "re", "reg":
		patternStr, ok := r.Find.(string)
		if !ok || patternStr == "" {
			return nil, fmt.Errorf("no regex pattern provided")
		}
		pattern, err := regexp.Compile(patternStr)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regex: %w", err)
		}
		replStr, ok := r.Replace.(string)
		if !ok {
			return nil, fmt.Errorf("replacement not of type string")
		}
		return &RegexReplacer{*pattern, replStr}, nil
	case "bytes":

		iFindBytes, ok := r.Find.([]interface{})
		if !ok {
			return nil, fmt.Errorf("find field not a slice: was %T", r.Replace)
		}
		iReplaceBytes, ok := r.Replace.([]interface{})
		if !ok {
			return nil, fmt.Errorf("find field is not a slice: was %T", r.Replace)
		}

		findBytes, err := parseByteSlice(iFindBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse search slice as bytes: %w", err)
		}
		replaceBytes, err := parseByteSlice(iReplaceBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse replace slice as bytes: %w", err)
		}

		if len(findBytes) == 0 {
			return nil, fmt.Errorf("no search bytes provided")
		}
		return &BytesReplacer{findBytes, replaceBytes}, nil
	default:
		return nil, fmt.Errorf("unsupported replacer type: <%s>", r.ReplacerType)
	}
}

func parseByteSlice(s []interface{}) ([]byte, error) {
	var bSlice []byte

	for i, elem := range s {
		iVal, ok := elem.(int)
		if !ok {
			return nil, fmt.Errorf("value of type %T at index %d", elem, i)
		}

		if iVal < 0 || iVal > 255 {
			return nil, fmt.Errorf("value out of range for byte: %d", iVal)
		}

		b := byte(iVal)
		bSlice = append(bSlice, b)
	}
	return bSlice, nil
}

func (p *Proxy) LoadConfig(config []byte) error {
	var errs error

	var configs []ReplacerConfig
	if err := yaml.Unmarshal(config, &configs); err != nil {
		return fmt.Errorf("error parsing config file: %v", err)
	}
	for _, r := range configs {
		replacer, err := r.Parse()
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("error parsing config item: %v", err))
		} else {
			p.Log.Info(replacer.String())
			p.Replacers = append(p.Replacers, replacer)
		}
	}
	return errs
}
