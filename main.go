package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ASTRA-LabsHQ/Astra-AV-Engine/scanner"
)

// ============================================================
// ASTRA AV Engine — Episode 2: YARA Rule Scanning
// main.go — CLI entry point
// ============================================================

const version = "0.2.0"

// defaultSigDB returns the path to the signature database relative to the binary.
func defaultSigDB() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("signatures", "hashes.txt")
	}
	return filepath.Join(filepath.Dir(exe), "signatures", "hashes.txt")
}

// defaultRulesDir returns the default YARA rules directory relative to the binary.
func defaultRulesDir() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("rules")
	}
	return filepath.Join(filepath.Dir(exe), "rules")
}

func printBanner() {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf(" Astra AV Engine v%s\n", version)
	fmt.Println(" Advanced Security Research and Analysis")
	fmt.Println(" Detection: Hash Signatures + YARA Rules")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
}

func printResult(r scanner.ScanResult) {
	if r.Error != nil {
		fmt.Printf(" [ERR] %s\n      %v\n\n", r.FilePath, r.Error)
		return
	}

	// ── Hash match ───────────────────────────────────────
	if r.Detected {
		fmt.Println(" [!] DETECTED (Hash) —", r.FilePath)
		fmt.Printf("     %-10s: %s\n", r.MatchType, r.MatchHash)
		fmt.Printf("     %-10s: %s\n", "Match", r.ThreatName)
		fmt.Printf("     %-10s: %s\n", "Verdict", r.Verdict)
		fmt.Printf("     %-10s: %s\n\n", "Scan time", r.ScanTime)
	}

	// ── YARA matches ─────────────────────────────────────
	if len(r.YaraMatches) > 0 {
		if !r.Detected {
			fmt.Println(" [!] DETECTED (YARA) —", r.FilePath)
			fmt.Printf("     %-10s: %s\n", "Verdict", r.Verdict)
		} else {
			fmt.Printf("     Also matched %d YARA rule(s):\n", len(r.YaraMatches))
		}

		for _, m := range r.YaraMatches {
			tags := ""
			if len(m.Tags) > 0 {
				tags = fmt.Sprintf(" [%s]", strings.Join(m.Tags, ", "))
			}
			fmt.Printf("     [YARA] %s::%s%s\n", m.Namespace, m.RuleName, tags)
			for _, s := range m.Strings {
				data := s.Data
				suffix := ""
				if len(data) > 32 {
					data = data[:32]
					suffix = "..."
				}
				fmt.Printf("            %s @ 0x%x : %q%s\n", s.Name, s.Offset, data, suffix)
			}
		}
		fmt.Printf("     %-10s: %s\n\n", "Scan time", r.ScanTime)
	}

	// ── Clean ────────────────────────────────────────────
	if !r.Detected && len(r.YaraMatches) == 0 {
		fmt.Printf(" [CLEAN] %s\n", r.FilePath)
	}
}

func printSummary(results []scanner.ScanResult, elapsed time.Duration) {
	total, hashDetected, yaraDetected, errors := 0, 0, 0, 0

	for _, r := range results {
		total++
		if r.Detected {
			hashDetected++
		}
		if len(r.YaraMatches) > 0 {
			yaraDetected++
		}
		if r.Error != nil {
			errors++
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf(" Scan complete    : %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf(" Files scanned    : %d\n", total)
	fmt.Printf(" Hash detections  : %d\n", hashDetected)
	fmt.Printf(" YARA detections  : %d\n", yaraDetected)
	fmt.Printf(" Errors           : %d\n", errors)
	fmt.Println(strings.Repeat("-", 60))

	if hashDetected+yaraDetected > 0 {
		fmt.Println("\n *** THREATS DETECTED — DO NOT EXECUTE FLAGGED FILES ***")
	} else {
		fmt.Println("\n No threats detected.")
	}
}

func main() {
	printBanner()

	// ── Subcommands ──────────────────────────────────────
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	scanFile := scanCmd.String("file", "", "Path to a single file to scan")
	scanDir := scanCmd.String("dir", "", "Path to a directory to scan recursively")
	scanDB := scanCmd.String("db", defaultSigDB(), "Path to signature database")
	scanRules := scanCmd.String("rules", "", "Path to a YARA rule file or directory (optional)")

	addCmd := flag.NewFlagSet("add-hash", flag.ExitOnError)
	addHash := addCmd.String("hash", "", "Hash value to add")
	addType := addCmd.String("type", "SHA256", "Hash type: MD5, SHA1, or SHA256")
	addName := addCmd.String("name", "", "Threat name (e.g. \"WannaCry Ransomware\")")
	addDB := addCmd.String("db", defaultSigDB(), "Path to signature database")

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  astra-av scan --file <path> [--rules <path>]")
		fmt.Fprintln(os.Stderr, "  astra-av scan --dir  <path> [--rules <path>]")
		fmt.Fprintln(os.Stderr, "  astra-av add-hash --hash <hash> --name <threat>")
		os.Exit(1)
	}

	switch os.Args[1] {

	// ── scan ─────────────────────────────────────────────
	case "scan":
		scanCmd.Parse(os.Args[2:])

		if *scanFile == "" && *scanDir == "" {
			fmt.Fprintln(os.Stderr, "[ERROR] Provide --file or --dir")
			scanCmd.Usage()
			os.Exit(1)
		}

		// Load hash signature database
		db, err := scanner.LoadSignatures(*scanDB)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Loaded %d hash signatures from %s\n", db.Count(), *scanDB)

		// Load YARA rules (optional)
		var ys *scanner.YaraScanner
		if *scanRules != "" {
			var ruleCount int
			ys, ruleCount, err = scanner.LoadYaraRules(*scanRules)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] YARA: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("[*] Loaded %d YARA rule file(s) from %s\n", ruleCount, *scanRules)
		} else {
			fmt.Println("[*] YARA scanning disabled (use --rules to enable)")
		}
		fmt.Println()

		start := time.Now()
		var results []scanner.ScanResult

		if *scanFile != "" {
			fmt.Printf("[*] Scanning file: %s\n\n", *scanFile)
			results = append(results, scanner.ScanFile(*scanFile, db, ys))
		} else {
			fmt.Printf("[*] Scanning directory: %s\n\n", *scanDir)
			results = scanner.ScanDirectory(*scanDir, db, ys)
		}

		for _, r := range results {
			printResult(r)
		}

		printSummary(results, time.Since(start))

	// ── add-hash ─────────────────────────────────────────
	case "add-hash":
		addCmd.Parse(os.Args[2:])

		if *addHash == "" || *addName == "" {
			fmt.Fprintln(os.Stderr, "[ERROR] --hash and --name are required")
			addCmd.Usage()
			os.Exit(1)
		}

		validTypes := map[string]bool{"MD5": true, "SHA1": true, "SHA256": true}
		hashType := strings.ToUpper(*addType)
		if !validTypes[hashType] {
			fmt.Fprintf(os.Stderr, "[ERROR] Invalid hash type %q — must be MD5, SHA1, or SHA256\n", *addType)
			os.Exit(1)
		}

		if err := scanner.AddSignature(*addDB, hashType, *addHash, *addName); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Added signature: %s|%s|%s\n", hashType, *addHash, *addName)

	default:
		fmt.Fprintf(os.Stderr, "[ERROR] Unknown command %q\n", os.Args[1])
		fmt.Fprintln(os.Stderr, "Commands: scan, add-hash")
		os.Exit(1)
	}
}
