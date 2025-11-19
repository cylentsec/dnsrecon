# Background and Purpose
This tool enriches domain lists by resolving each domain to its IP address and identifying the organization that owns the IP block. This helps you determine which domains are actually in scope for your pentest by showing the real infrastructure owners.

The tool reads domains from stdin (pipe input), resolves each to an IPv4 address, then performs whois lookups to identify the organization that owns each IP block. It supports multiple regional internet registries (ARIN, RIPE, APNIC, etc.) and handles rate limiting gracefully.

This is perfect for processing output from subdomain enumeration tools like chaos, subfinder, or amass to add context about which domains are owned by your target organization vs third-party providers.

# Setup

## Install dnsrecon (Go version - Recommended):

```bash
go install github.com/sdcampbell/dnsrecon@latest
```

## Install the Chaos client:

```bash
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
```

## Set the Chaos client API key:

Signup to get your API key here: https://chaos.projectdiscovery.io/docs/quick-start

Set the key in your .bashrc or .zshrc file:

```bash
export CHAOS_KEY=<your API key here>
```

# Execution

The tool reads domains from stdin and outputs semicolon-separated results:

```bash
# Using with chaos client
chaos -d example.com | dnsrecon

# Using with file input
cat domains.txt | dnsrecon

# Using with subfinder
subfinder -d example.com | dnsrecon

# Using with amass
amass enum -d example.com | dnsrecon
```

Check version:
```bash
dnsrecon -version
```

## Scope Filtering

Use the `-scope` flag to filter results based on a scope file:

```bash
# Filter output to only show in-scope results
cat domains.txt | dnsrecon -scope
```

The `scope.txt` file should be in the current working directory and contain one entry per line:
- Domain names (exact match only, not subdomains): `example.com`
- IP addresses: `192.168.1.1`
- Network ranges in CIDR notation: `10.0.0.0/8`

Matching rules:
- Domain must match exactly (case-insensitive)
- IP address must match exactly OR be within a CIDR range
- Any match (domain OR IP) will include the result

Example scope.txt:
```
example.com
203.0.113.10
198.51.100.0/24
2001:db8::/32
```

If `scope.txt` is not found when using `-scope`, a warning is printed to stderr and no results are shown.

There are no banners or progress bars. The output is semi-colon separated for easy parsing with awk/grep/cut/Excel.

# Example output

```
vhnokia-gw.example.com;12.32.90.147;AT&T Services, Inc.
vhvpn.example.com;12.32.90.179;AT&T Services, Inc.
view.example.com;63.85.196.11;Verizon Business
viewlab.uk.example.com;91.240.17.234;
visionapp-den.services.example.com;64.73.81.63;Example Technologies LLC
visionapp-msp.services.example.com;64.73.65.63;Example Technologies LLC
visionapp.services.example.com;64.73.65.63;Example Technologies LLC
vmrc.uk.example.com;194.105.149.148;
voicetotext.example.com;52.149.215.200;Microsoft Corporation
voip.example.com;12.32.91.66;AT&T Services, Inc.
webapppd.azr.example.com;52.162.107.30;Microsoft Corporation
webapps.example.com;52.149.215.200;Microsoft Corporation
webappsstg.example.com;52.149.215.200;Microsoft Corporation
webcon15.ms.example.com;64.73.23.241;Example Technologies LLC
webcon15.s3.example.com;64.73.23.241;Example Technologies LLC
webmail.example.com;52.149.215.200;Microsoft Corporation
webobjects.example.com;184.24.66.246;Akamai Technologies, Inc.
webobjects2.example.com;184.24.66.246;Akamai Technologies, Inc.
webobjects2beta.example.com;96.7.27.87;Akamai Technologies, Inc.
webportal.example.com;12.32.90.94;AT&T Services, Inc.
webstage.example.com;184.25.36.105;Akamai Technologies, Inc.
webstage.wip.example.com;64.73.16.247;Example Technologies LLC
wifienroll.example.com;52.149.215.200;Microsoft Corporation
www.example.com;184.24.66.246;Akamai Technologies, Inc.
www.mpt.example.com;137.135.86.148;Microsoft Corp
www.uk.example.com;184.24.64.58;Akamai Technologies, Inc.
xenmobilelab.uk.example.com;91.240.17.10;
12-32-90-100.example.com;12.32.90.100;AT&T Services, Inc.
12-32-90-101.example.com;12.32.90.101;AT&T Services, Inc.
```
