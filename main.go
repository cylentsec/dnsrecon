package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var (
	version = "v1.2.0"
	commit  = "none"
	date    = "unknown"
)

func resolveDomain(domain string) (string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found")
}

func isRateLimited(output string, err error) bool {
	if err != nil {
		return false
	}

	output = strings.ToLower(output)
	rateLimitIndicators := []string{
		"rate limit",
		"too many",
		"query limit",
		"exceeded",
		"throttled",
		"temporarily unavailable",
		"service unavailable",
	}

	for _, indicator := range rateLimitIndicators {
		if strings.Contains(output, indicator) {
			return true
		}
	}

	return false
}

func getOrganizationWithRetry(ip string, maxRetries int) (string, error) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		cmd := exec.Command("whois", ip)
		cmd.Env = os.Environ()

		// Set timeout for whois command
		if attempt > 0 {
			// Add exponential backoff delay before retry
			backoffDelay := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			time.Sleep(backoffDelay)
		}

		output, err := cmd.Output()
		outputStr := string(output)

		// Check for rate limiting
		if isRateLimited(outputStr, err) {
			if attempt < maxRetries-1 {
				continue // Retry with backoff
			}
			return "", fmt.Errorf("rate limited after %d attempts", maxRetries)
		}

		// If command failed for other reasons, return empty (don't retry)
		if err != nil {
			return "", nil
		}

		// Parse successful output - handle different registry formats
		// Priority order: most specific to least specific
		var candidates []string
		scanner := bufio.NewScanner(strings.NewReader(outputStr))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "OrgName:") || // ARIN format (high priority)
				strings.HasPrefix(line, "org-name:") || // RIPE format (high priority)
				strings.HasPrefix(line, "Organization:") { // Other formats (medium priority)
				cleaned := regexp.MustCompile(`\s+`).ReplaceAllString(line, " ")
				parts := strings.Split(cleaned, " ")
				if len(parts) > 1 {
					candidates = append(candidates, strings.Join(parts[1:], " "))
				}
			}
		}

		// Return the first (highest priority) candidate
		if len(candidates) > 0 {
			return candidates[0], nil
		}

		// No OrgName found, but no error - return empty
		return "", nil
	}

	return "", fmt.Errorf("max retries exceeded")
}

func getOrganization(ip string) (string, error) {
	return getOrganizationWithRetry(ip, 3) // Max 3 attempts with exponential backoff
}


func main() {
	var showVersion bool
	var scopeFlag bool
	flag.BoolVar(&showVersion, "version", false, "show version information")
	flag.BoolVar(&scopeFlag, "scope", false, "filter output using scope.txt (domains, IPs, or CIDRs)")
	flag.Parse()

	if showVersion {
		fmt.Printf("dnsrecon %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	if flag.NArg() != 0 {
		fmt.Println("This tool reads domains from stdin/pipe input.")
		fmt.Printf("Usage: cat domains.txt | %s [-version] [-scope]\n", os.Args[0])
		fmt.Printf("   or: chaos -d example.com | %s\n", os.Args[0])
		os.Exit(1)
	}

	// Load scope if needed
	var scope Scope
	if scopeFlag {
		var err error
		scope, err = LoadScope("scope.txt")
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Warning: scope.txt not found; no results will be printed with -scope\n")
			} else {
				fmt.Fprintf(os.Stderr, "Warning: error reading scope.txt: %v\n", err)
			}
			// Empty scope means no matches
			scope = Scope{
				domains: make(map[string]struct{}),
				ips:     make(map[string]struct{}),
				nets:    []*net.IPNet{},
			}
		}
	}

	// Process domains line-by-line with streaming output
	scanner := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	seen := make(map[string]bool)
	domainCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(line, "*") {
			continue
		}

		// Skip duplicates
		if seen[line] {
			continue
		}
		seen[line] = true
		domainCount++

		// Resolve domain
		ip, err := resolveDomain(line)
		if err != nil {
			continue
		}

		// Get organization
		org, _ := getOrganization(ip)

		// Apply scope filter if requested
		if scopeFlag {
			var parsedIP net.IP
			if ip != "" {
				parsedIP = net.ParseIP(ip)
			}
			if scope.Contains(line, parsedIP) {
				fmt.Printf("%s;%s;%s\n", line, ip, org)
			}
		} else {
			fmt.Printf("%s;%s;%s\n", line, ip, org)
		}

		// Add small delay between requests to be respectful to whois servers
		time.Sleep(100 * time.Millisecond)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		os.Exit(1)
	}

	if domainCount == 0 {
		fmt.Fprintf(os.Stderr, "No domains provided in stdin\n")
		os.Exit(1)
	}
}
