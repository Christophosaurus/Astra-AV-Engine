package scanner

// ============================================================
// ASTRA AV Engine — Episode 2: YARA Rule Scanning
// scanner/yara.go — YARA scanning logic
// ============================================================

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hillu/go-yara/v4"
)

// YaraMatch holds the details of a single YARA rule match.
type YaraMatch struct {
	RuleName  string
	Namespace string
	Tags      []string
	Strings   []YaraMatchString
}

// YaraMatchString holds a single matched string from a YARA rule.
type YaraMatchString struct {
	Name   string
	Offset uint64
	Data   []byte
}

// YaraScanner wraps a compiled YARA ruleset.
type YaraScanner struct {
	rules *yara.Rules
}

// LoadYaraRules compiles all .yar / .yara files from the given path.
// path can be a single file or a directory — if a directory is provided,
// all rule files inside it are compiled into a single ruleset.
func LoadYaraRules(path string) (*YaraScanner, int, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create YARA compiler: %w", err)
	}

	rulesLoaded := 0

	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, fmt.Errorf("could not access YARA rules path: %w", err)
	}

	if info.IsDir() {
		// Walk the directory and compile every .yar / .yara file found
		err = filepath.Walk(path, func(p string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if fi.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext != ".yar" && ext != ".yara" {
				return nil
			}
			f, err := os.Open(p)
			if err != nil {
				return fmt.Errorf("could not open rule file %s: %w", p, err)
			}
			defer f.Close()

			// Use the filename (without extension) as the namespace
			ns := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
			if err := compiler.AddFile(f, ns); err != nil {
				return fmt.Errorf("error compiling %s: %w", p, err)
			}
			rulesLoaded++
			return nil
		})
		if err != nil {
			return nil, 0, err
		}
	} else {
		// Single rule file
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, fmt.Errorf("could not open rule file: %w", err)
		}
		defer f.Close()

		ns := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if err := compiler.AddFile(f, ns); err != nil {
			return nil, 0, fmt.Errorf("error compiling YARA rules: %w", err)
		}
		rulesLoaded++
	}

	if rulesLoaded == 0 {
		return nil, 0, fmt.Errorf("no .yar or .yara files found at: %s", path)
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to compile YARA rules: %w", err)
	}

	return &YaraScanner{rules: rules}, rulesLoaded, nil
}

// ScanFileYara runs the compiled YARA ruleset against a single file.
// Returns a slice of YaraMatch — one entry per matching rule.
func (ys *YaraScanner) ScanFileYara(path string) ([]YaraMatch, error) {
	var matches yara.MatchRules
	if err := ys.rules.ScanFile(path, 0, 0, &matches); err != nil {
		return nil, fmt.Errorf("YARA scan error on %s: %w", path, err)
	}

	var results []YaraMatch
	for _, m := range matches {
		match := YaraMatch{
			RuleName:  m.Rule,
			Namespace: m.Namespace,
			Tags:      m.Tags,
		}
		for _, s := range m.Strings {
			match.Strings = append(match.Strings, YaraMatchString{
				Name:   s.Name,
				Offset: s.Offset,
				Data:   s.Data,
			})
		}
		results = append(results, match)
	}

	return results, nil
}
