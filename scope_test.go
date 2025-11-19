package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase", "example.com", "example.com"},
		{"uppercase", "EXAMPLE.COM", "example.com"},
		{"mixed case", "ExAmPlE.CoM", "example.com"},
		{"trailing dot", "example.com.", "example.com"},
		{"whitespace", "  example.com  ", "example.com"},
		{"trailing dot and whitespace", "  example.com.  ", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeDomain(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeIPString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"IPv4", "192.168.1.1", "192.168.1.1"},
		{"IPv6", "2001:db8::1", "2001:db8::1"},
		{"IPv4-mapped IPv6", "::ffff:192.168.1.1", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.input)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.input)
			}
			result := normalizeIPString(ip)
			if result != tt.expected {
				t.Errorf("normalizeIPString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestLoadScope(t *testing.T) {
	tests := []struct {
		name            string
		content         string
		expectedDomains []string
		expectedIPs     []string
		expectedNets    []string
	}{
		{
			name:            "mixed content",
			content:         "example.com\n192.168.1.1\n10.0.0.0/8\n",
			expectedDomains: []string{"example.com"},
			expectedIPs:     []string{"192.168.1.1"},
			expectedNets:    []string{"10.0.0.0/8"},
		},
		{
			name:            "domains only",
			content:         "example.com\ntest.org\nfoo.bar\n",
			expectedDomains: []string{"example.com", "test.org", "foo.bar"},
			expectedIPs:     []string{},
			expectedNets:    []string{},
		},
		{
			name:            "IPs only",
			content:         "192.168.1.1\n10.20.30.40\n2001:db8::1\n",
			expectedDomains: []string{},
			expectedIPs:     []string{"192.168.1.1", "10.20.30.40", "2001:db8::1"},
			expectedNets:    []string{},
		},
		{
			name:            "networks only",
			content:         "192.168.0.0/16\n10.0.0.0/8\n2001:db8::/32\n",
			expectedDomains: []string{},
			expectedIPs:     []string{},
			expectedNets:    []string{"192.168.0.0/16", "10.0.0.0/8", "2001:db8::/32"},
		},
		{
			name:            "empty lines and whitespace",
			content:         "\n  \nexample.com\n\n  192.168.1.1  \n\n",
			expectedDomains: []string{"example.com"},
			expectedIPs:     []string{"192.168.1.1"},
			expectedNets:    []string{},
		},
		{
			name:            "case insensitive domains",
			content:         "EXAMPLE.COM\nExample.Com\n",
			expectedDomains: []string{"example.com"},
			expectedIPs:     []string{},
			expectedNets:    []string{},
		},
		{
			name:            "trailing dots",
			content:         "example.com.\ntest.org.\n",
			expectedDomains: []string{"example.com", "test.org"},
			expectedIPs:     []string{},
			expectedNets:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "scope.txt")
			if err := os.WriteFile(tmpFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}

			// Load scope
			scope, err := LoadScope(tmpFile)
			if err != nil {
				t.Fatalf("LoadScope failed: %v", err)
			}

			// Check domains
			if len(scope.domains) != len(tt.expectedDomains) {
				t.Errorf("Expected %d domains, got %d", len(tt.expectedDomains), len(scope.domains))
			}
			for _, domain := range tt.expectedDomains {
				if _, exists := scope.domains[domain]; !exists {
					t.Errorf("Expected domain %q not found", domain)
				}
			}

			// Check IPs
			if len(scope.ips) != len(tt.expectedIPs) {
				t.Errorf("Expected %d IPs, got %d", len(tt.expectedIPs), len(scope.ips))
			}
			for _, ipStr := range tt.expectedIPs {
				ip := net.ParseIP(ipStr)
				normalized := normalizeIPString(ip)
				if _, exists := scope.ips[normalized]; !exists {
					t.Errorf("Expected IP %q (normalized: %q) not found", ipStr, normalized)
				}
			}

			// Check networks
			if len(scope.nets) != len(tt.expectedNets) {
				t.Errorf("Expected %d networks, got %d", len(tt.expectedNets), len(scope.nets))
			}
		})
	}
}

func TestScopeContains(t *testing.T) {
	// Create a scope with known entries
	scope := Scope{
		domains: map[string]struct{}{
			"example.com": {},
			"test.org":    {},
		},
		ips: map[string]struct{}{
			"192.168.1.1": {},
			"10.20.30.40": {},
		},
		nets: []*net.IPNet{},
	}

	// Add network ranges
	_, net1, _ := net.ParseCIDR("10.0.0.0/8")
	_, net2, _ := net.ParseCIDR("172.16.0.0/12")
	scope.nets = append(scope.nets, net1, net2)

	tests := []struct {
		name     string
		domain   string
		ipStr    string
		expected bool
	}{
		// Domain exact matches
		{"exact domain match", "example.com", "", true},
		{"exact domain match uppercase", "EXAMPLE.COM", "", true},
		{"exact domain match trailing dot", "example.com.", "", true},
		{"subdomain no match", "sub.example.com", "", false},
		{"different domain", "other.com", "", false},

		// IP exact matches
		{"exact IP match", "", "192.168.1.1", true},
		{"exact IP match 2", "", "10.20.30.40", true},
		{"IP no match", "", "1.2.3.4", false},

		// Network range matches
		{"IP in network range 1", "", "10.50.60.70", true},
		{"IP in network range 2", "", "172.16.1.1", true},
		{"IP not in network range", "", "11.0.0.1", false},

		// Combined matches
		{"domain match with IP", "example.com", "192.168.1.1", true},
		{"domain match IP no match", "example.com", "1.2.3.4", true},
		{"domain no match IP match", "other.com", "192.168.1.1", true},
		{"neither match", "other.com", "1.2.3.4", false},

		// Edge cases
		{"empty domain and IP", "", "", false},
		{"only domain empty", "", "1.2.3.4", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip net.IP
			if tt.ipStr != "" {
				ip = net.ParseIP(tt.ipStr)
			}

			result := scope.Contains(tt.domain, ip)
			if result != tt.expected {
				t.Errorf("Contains(%q, %q) = %v, want %v", tt.domain, tt.ipStr, result, tt.expected)
			}
		})
	}
}

func TestLoadScopeFileNotFound(t *testing.T) {
	_, err := LoadScope("/nonexistent/scope.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
	if !os.IsNotExist(err) {
		t.Errorf("Expected IsNotExist error, got: %v", err)
	}
}

func TestLoadScopeInvalidCIDR(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "scope.txt")
	content := "example.com\n192.168.1.1/99\n10.0.0.0/8\n"
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	scope, err := LoadScope(tmpFile)
	if err != nil {
		t.Fatalf("LoadScope failed: %v", err)
	}

	// Should have 1 domain, 0 IPs, 1 network (invalid CIDR skipped)
	if len(scope.domains) != 1 {
		t.Errorf("Expected 1 domain, got %d", len(scope.domains))
	}
	if len(scope.ips) != 0 {
		t.Errorf("Expected 0 IPs, got %d", len(scope.ips))
	}
	if len(scope.nets) != 1 {
		t.Errorf("Expected 1 network (invalid CIDR should be skipped), got %d", len(scope.nets))
	}
}

func TestScopeContainsIPv6(t *testing.T) {
	scope := Scope{
		domains: map[string]struct{}{},
		ips: map[string]struct{}{
			"2001:db8::1": {},
		},
		nets: []*net.IPNet{},
	}

	_, net1, _ := net.ParseCIDR("2001:db8::/32")
	scope.nets = append(scope.nets, net1)

	tests := []struct {
		name     string
		ipStr    string
		expected bool
	}{
		{"exact IPv6 match", "2001:db8::1", true},
		{"IPv6 in range", "2001:db8::ffff", true},
		{"IPv6 not in range", "2001:db9::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ipStr)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ipStr)
			}

			result := scope.Contains("", ip)
			if result != tt.expected {
				t.Errorf("Contains(\"\", %q) = %v, want %v", tt.ipStr, result, tt.expected)
			}
		})
	}
}
