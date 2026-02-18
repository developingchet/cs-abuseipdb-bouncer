package abuseipdb

import (
	"strings"
)

type rule struct {
	patterns   []string
	categories []int
}

// Ordered mapping table. First match wins.
// Ported from the shell script's categories() function with exact same priority.
var rules = []rule{
	// Priority 1: SSH
	{[]string{"ssh"}, []int{CatSSH, CatBruteForce}},
	// Priority 2: FTP
	{[]string{"ftp"}, []int{CatFTPBruteForce, CatBruteForce}},
	// Priority 3: SQL injection
	{[]string{"sqli", "sql-inj", "sql_inj"}, []int{CatSQLInjection, CatWebAppAttack}},
	// Priority 4: XSS
	{[]string{"xss"}, []int{CatWebAppAttack}},
	// Priority 5: CMS
	{[]string{"wordpress", "wp-login", "wp_login", "drupal", "joomla", "magento", "prestashop"}, []int{CatBruteForce, CatWebAppAttack}},
	// Priority 6: Ping/ICMP -- must precede DDoS/flood to avoid "ping-flood" matching flood first
	{[]string{"ping", "icmp"}, []int{CatPingOfDeath}},
	// Priority 7: DDoS
	{[]string{"http-dos", "http-flood", "ddos", "flood", "-dos"}, []int{CatDDoSAttack}},
	// Priority 8: Proxy/Tor
	{[]string{"open-proxy", "open_proxy", "proxy", "tor"}, []int{CatOpenProxy}},
	// Priority 9: Bad bots
	{[]string{"crawl", "bad-user-agent", "bad_user_agent", "robot", "scraper", "spider", "w00tw00t"}, []int{CatBadWebBot}},
	// Priority 10: Specific scanner tools -- must precede generic scan to avoid overlap
	{[]string{"nmap", "masscan", "zmap", "iptables"}, []int{CatPortScan}},
	// Priority 11: AppSec
	{[]string{"appsec", "vpatch"}, []int{CatWebAppAttack}},
	// Priority 12: Exploits -- must precede probing/scan so "path-traversal-probing" matches traversal not probing
	{[]string{"backdoor", "rce", "exploit", "lfi", "rfi", "traversal", "path-trav", "log4", "spring4", "sensitive"}, []int{CatWebAppAttack, CatExploitedHost}},
	// Priority 13: CVE
	{[]string{"cve"}, []int{CatWebAppAttack, CatExploitedHost}},
	// Priority 14: Probing/Scanning (generic)
	{[]string{"probing", "scan", "enum"}, []int{CatPortScan, CatWebAppAttack}},
	// Priority 15: IoT
	{[]string{"iot", "mirai", "telnet"}, []int{CatIoTTargeted, CatExploitedHost}},
	// Priority 16: Email spam
	{[]string{"smtp", "email-spam", "email_spam", "imap", "pop3"}, []int{CatEmailSpam, CatBruteForce}},
	// Priority 17: Web spam -- must precede http/web to avoid "http-spam" matching http first
	{[]string{"http-spam", "web-spam", "comment-spam", "blog-spam", "comment_spam"}, []int{CatWebSpam, CatBlogSpam}},
	// Priority 18: Phishing
	{[]string{"phish"}, []int{CatPhishing}},
	// Priority 19: Spoofing
	{[]string{"spoof"}, []int{CatSpoofing}},
	// Priority 20: VPN
	{[]string{"vpn"}, []int{CatVPNIP}},
	// Priority 21: DNS
	{[]string{"dns"}, []int{CatDNSCompromise}},
	// Priority 22: VoIP
	{[]string{"voip"}, []int{CatFraudVoIP}},
	// Priority 23: Fraud
	{[]string{"fraud", "card"}, []int{CatFraudOrders}},
	// Priority 24: Authelia
	{[]string{"authelia"}, []int{CatBruteForce}},
	// Priority 25: Port scan (generic)
	{[]string{"port"}, []int{CatPortScan}},
	// Priority 26: Generic web -- must precede brute/-bf so "nginx-bf" matches nginx not -bf
	{[]string{"http", "web", "nginx", "apache", "iis"}, []int{CatWebAppAttack}},
	// Priority 27: Generic brute force
	{[]string{"brute", "-bf", "_bf", "rdp", "sip", "vnc"}, []int{CatBruteForce}},
}

// MapScenario converts a CrowdSec scenario name to AbuseIPDB category IDs.
// The scenario is lowercased and the author prefix is stripped before matching.
// First match wins; returns {15} (Hacking) if no pattern matches.
func MapScenario(scenario string) []int {
	s := strings.ToLower(scenario)

	// Strip author prefix: "crowdsecurity/ssh-bf" -> "ssh-bf"
	if idx := strings.LastIndex(s, "/"); idx != -1 {
		s = s[idx+1:]
	}

	for _, r := range rules {
		for _, pattern := range r.patterns {
			if strings.Contains(s, pattern) {
				return r.categories
			}
		}
	}

	return []int{CatHacking}
}
