package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Scope represents the filtering criteria from scope.txt
type Scope struct {
	domains map[string]struct{}
	ips     map[string]struct{}
	nets    []*net.IPNet
}

// normalizeDomain normalizes a domain name for comparison
func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

// normalizeIPString converts an IP to its canonical string representation
func normalizeIPString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	// Always prefer IPv4 representation if applicable
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.String()
	}
	return ip.String()
}

// LoadScope reads and parses the scope.txt file
func LoadScope(path string) (Scope, error) {
	scope := Scope{
		domains: make(map[string]struct{}),
		ips:     make(map[string]struct{}),
		nets:    []*net.IPNet{},
	}

	file, err := os.Open(path)
	if err != nil {
		return scope, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Try parsing as CIDR network
		if strings.Contains(line, "/") {
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: invalid CIDR on line %d: %s\n", lineNum, line)
				continue
			}
			scope.nets = append(scope.nets, ipNet)
			continue
		}

		// Try parsing as IP address
		if ip := net.ParseIP(line); ip != nil {
			normalized := normalizeIPString(ip)
			scope.ips[normalized] = struct{}{}
			continue
		}

		// Treat as domain
		normalized := normalizeDomain(line)
		scope.domains[normalized] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		return scope, err
	}

	return scope, nil
}

// Contains checks if the given domain or IP matches the scope
func (s Scope) Contains(domain string, ip net.IP) bool {
	// Check domain match (exact match only, not subdomains)
	if domain != "" {
		normalized := normalizeDomain(domain)
		if _, exists := s.domains[normalized]; exists {
			return true
		}
	}

	// Check IP match
	if ip != nil {
		// Check exact IP match
		normalized := normalizeIPString(ip)
		if _, exists := s.ips[normalized]; exists {
			return true
		}

		// Check if IP is in any network range
		for _, network := range s.nets {
			if network.Contains(ip) {
				return true
			}
		}
	}

	return false
}
