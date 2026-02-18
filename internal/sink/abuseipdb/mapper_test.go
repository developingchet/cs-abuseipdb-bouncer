package abuseipdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapScenario(t *testing.T) {
	tests := []struct {
		scenario string
		expected []int
		desc     string
	}{
		// Priority 1: SSH
		{"crowdsecurity/ssh-bf", []int{CatSSH, CatBruteForce}, "ssh brute force"},
		{"crowdsecurity/ssh-slow-bf", []int{CatSSH, CatBruteForce}, "ssh slow brute force"},
		{"ssh-cve-2024-6387", []int{CatSSH, CatBruteForce}, "ssh CVE (ssh matches before cve)"},

		// Priority 2: FTP
		{"crowdsecurity/ftp-bf", []int{CatFTPBruteForce, CatBruteForce}, "ftp brute force"},

		// Priority 3: SQL injection
		{"http-sqli-probing", []int{CatSQLInjection, CatWebAppAttack}, "sql injection probing"},
		{"sql-injection-attempt", []int{CatSQLInjection, CatWebAppAttack}, "sql-inj pattern"},
		{"sql_injection", []int{CatSQLInjection, CatWebAppAttack}, "sql_inj pattern"},

		// Priority 4: XSS
		{"http-xss-probing", []int{CatWebAppAttack}, "xss probing"},

		// Priority 5: CMS
		{"http-bf-wordpress_bf", []int{CatBruteForce, CatWebAppAttack}, "wordpress brute force"},
		{"wordpress-scan", []int{CatBruteForce, CatWebAppAttack}, "wordpress scan"},
		{"drupal-cve-2018-7600", []int{CatBruteForce, CatWebAppAttack}, "drupal CVE"},
		{"joomla-bf", []int{CatBruteForce, CatWebAppAttack}, "joomla brute force"},
		{"wp-login-bf", []int{CatBruteForce, CatWebAppAttack}, "wp-login brute force"},

		// Priority 6: Ping/ICMP -- precedes DDoS so "ping-flood" matches PingOfDeath not DDoS
		{"ping-flood", []int{CatPingOfDeath}, "ping-flood matches ping before flood"},
		{"icmp-flood", []int{CatPingOfDeath}, "icmp flood"},

		// Priority 7: DDoS
		{"http-dos-generic", []int{CatDDoSAttack}, "HTTP DoS"},
		{"ddos", []int{CatDDoSAttack}, "plain ddos"},
		{"syn-flood", []int{CatDDoSAttack}, "syn flood"},
		{"http-flood", []int{CatDDoSAttack}, "http flood"},

		// Priority 8: Proxy/Tor
		{"http-open-proxy", []int{CatOpenProxy}, "open proxy"},
		{"tor-exit-node", []int{CatOpenProxy}, "tor exit node"},

		// Priority 9: Bad bots
		{"http-crawl-non_statics", []int{CatBadWebBot}, "web crawler"},
		{"bad-user-agent", []int{CatBadWebBot}, "bad user agent"},
		{"w00tw00t", []int{CatBadWebBot}, "w00tw00t scanner"},

		// Priority 10: Specific scanner tools (PortScan only -- precedes generic scan)
		{"iptables-scan-multi_ports", []int{CatPortScan}, "iptables scan (specific tool rule matches before generic scan)"},
		{"nmap-scan", []int{CatPortScan}, "nmap scan"},
		{"masscan-sweep", []int{CatPortScan}, "masscan"},

		// Priority 11: AppSec
		{"appsec-native", []int{CatWebAppAttack}, "appsec native"},
		{"vpatch-env-access", []int{CatWebAppAttack}, "vpatch"},

		// Priority 12: Exploits -- precedes probing/scan so "path-traversal-probing" matches traversal not probing
		{"http-backdoors-attempts", []int{CatWebAppAttack, CatExploitedHost}, "backdoor"},
		{"path-traversal-probing", []int{CatWebAppAttack, CatExploitedHost}, "path traversal"},
		{"apache-log4j2-cve-2021-44228", []int{CatWebAppAttack, CatExploitedHost}, "log4j (matches log4 pattern)"},
		{"rce-attempt", []int{CatWebAppAttack, CatExploitedHost}, "RCE"},
		{"lfi-attempt", []int{CatWebAppAttack, CatExploitedHost}, "LFI"},
		{"rfi-attempt", []int{CatWebAppAttack, CatExploitedHost}, "RFI"},

		// Priority 13: CVE
		{"grafana-cve-2021-43798", []int{CatWebAppAttack, CatExploitedHost}, "grafana CVE"},

		// Priority 14: Probing/Scanning (generic)
		{"http-probing", []int{CatPortScan, CatWebAppAttack}, "http probing"},

		// Priority 15: IoT
		{"mirai-generic", []int{CatIoTTargeted, CatExploitedHost}, "mirai"},
		{"telnet-bf", []int{CatIoTTargeted, CatExploitedHost}, "telnet"},

		// Priority 16: Email spam
		{"smtp-spam", []int{CatEmailSpam, CatBruteForce}, "smtp spam"},
		{"imap-bf", []int{CatEmailSpam, CatBruteForce}, "imap brute force"},

		// Priority 17: Web spam -- precedes http/web so "http-spam" matches web spam not web app attack
		{"http-spam", []int{CatWebSpam, CatBlogSpam}, "http spam"},
		{"blog-comment-spam", []int{CatWebSpam, CatBlogSpam}, "blog comment spam"},

		// Priority 18: Phishing
		{"phishing-url", []int{CatPhishing}, "phishing"},

		// Priority 19: Spoofing
		{"ip-spoofing", []int{CatSpoofing}, "spoofing"},

		// Priority 20: VPN
		{"vpn-detection", []int{CatVPNIP}, "vpn"},

		// Priority 21: DNS
		{"dns-amplification", []int{CatDNSCompromise}, "dns"},

		// Priority 22: VoIP
		{"voip-bf", []int{CatFraudVoIP}, "voip"},

		// Priority 23: Fraud
		{"credit-card-fraud", []int{CatFraudOrders}, "fraud"},

		// Priority 24: Authelia
		{"LePresidente/authelia-bf", []int{CatBruteForce}, "authelia brute force"},

		// Priority 25: Port scan (generic)
		// (no dedicated test case -- "port" is a substring of many things;
		//  nmap/masscan/iptables are already covered at Priority 10)

		// Priority 26: Generic web -- precedes brute/-bf so "nginx-bf" matches nginx not -bf
		{"nginx-bf", []int{CatWebAppAttack}, "nginx brute force"},
		{"apache-generic", []int{CatWebAppAttack}, "apache generic"},

		// Priority 27: Generic brute force
		{"generic-bf", []int{CatBruteForce}, "generic brute force"},
		{"rdp-bf", []int{CatBruteForce}, "rdp brute force"},
		{"sip-bf", []int{CatBruteForce}, "sip brute force"},
		{"vnc-bf", []int{CatBruteForce}, "vnc brute force"},

		// Default fallback
		{"unknown-scenario", []int{CatHacking}, "unknown falls back to hacking"},
		{"completely-random", []int{CatHacking}, "random falls back to hacking"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := MapScenario(tt.scenario)
			assert.Equal(t, tt.expected, result, "MapScenario(%q)", tt.scenario)
		})
	}
}

func TestMapScenario_CaseInsensitive(t *testing.T) {
	assert.Equal(t, []int{CatSSH, CatBruteForce}, MapScenario("SSH-BF"))
	assert.Equal(t, []int{CatSSH, CatBruteForce}, MapScenario("CrowdSecurity/SSH-BF"))
}

func TestMapScenario_AuthorPrefixStripping(t *testing.T) {
	// Both should produce the same result after stripping the prefix
	assert.Equal(t, MapScenario("crowdsecurity/ssh-bf"), MapScenario("myorg/ssh-bf"))
	assert.Equal(t, MapScenario("crowdsecurity/http-probing"), MapScenario("http-probing"))
}

func TestMapScenario_PriorityOrdering(t *testing.T) {
	// "ssh" (P1) before "cve" (P13): "ssh-cve-2024-6387" matches SSH
	result := MapScenario("ssh-cve-2024-6387")
	assert.Equal(t, []int{CatSSH, CatBruteForce}, result,
		"ssh should match before cve in priority ordering")

	// "ping" (P6) before "flood" (P7): "ping-flood" matches Ping of Death not DDoS
	result = MapScenario("ping-flood")
	assert.Equal(t, []int{CatPingOfDeath}, result,
		"ping should match before flood in priority ordering")

	// "traversal" (P12) before "probing" (P14): "path-traversal-probing" matches Exploited Host
	result = MapScenario("path-traversal-probing")
	assert.Equal(t, []int{CatWebAppAttack, CatExploitedHost}, result,
		"traversal should match before probing in priority ordering")

	// "probing" (P14) before "http" (P26): "http-probing" matches PortScan+WebApp not just WebApp
	result = MapScenario("http-probing")
	assert.Equal(t, []int{CatPortScan, CatWebAppAttack}, result,
		"probing should match before http in priority ordering")

	// "nginx" (P26) before "-bf" (P27): "nginx-bf" matches WebAppAttack not BruteForce
	result = MapScenario("nginx-bf")
	assert.Equal(t, []int{CatWebAppAttack}, result,
		"nginx should match before -bf in priority ordering")
}
