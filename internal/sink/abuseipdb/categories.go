package abuseipdb

// AbuseIPDB category IDs.
// Source: https://www.abuseipdb.com/categories
const (
	CatDNSCompromise  = 1
	CatDNSPoisoning   = 2
	CatFraudOrders    = 3
	CatDDoSAttack     = 4
	CatFTPBruteForce  = 5
	CatPingOfDeath    = 6
	CatPhishing       = 7
	CatFraudVoIP      = 8
	CatOpenProxy      = 9
	CatWebSpam        = 10
	CatEmailSpam      = 11
	CatBlogSpam       = 12
	CatVPNIP          = 13
	CatPortScan       = 14
	CatHacking        = 15
	CatSQLInjection   = 16
	CatSpoofing       = 17
	CatBruteForce     = 18
	CatBadWebBot      = 19
	CatExploitedHost  = 20
	CatWebAppAttack   = 21
	CatSSH            = 22
	CatIoTTargeted    = 23
)

// CategoryName maps category IDs to their display names.
var CategoryName = map[int]string{
	CatDNSCompromise:  "DNS Compromise",
	CatDNSPoisoning:   "DNS Poisoning",
	CatFraudOrders:    "Fraud Orders",
	CatDDoSAttack:     "DDoS Attack",
	CatFTPBruteForce:  "FTP Brute-Force",
	CatPingOfDeath:    "Ping of Death",
	CatPhishing:       "Phishing",
	CatFraudVoIP:      "Fraud VoIP",
	CatOpenProxy:      "Open Proxy",
	CatWebSpam:        "Web Spam",
	CatEmailSpam:      "Email Spam",
	CatBlogSpam:       "Blog Spam",
	CatVPNIP:          "VPN IP",
	CatPortScan:       "Port Scan",
	CatHacking:        "Hacking",
	CatSQLInjection:   "SQL Injection",
	CatSpoofing:       "Spoofing",
	CatBruteForce:     "Brute-Force",
	CatBadWebBot:      "Bad Web Bot",
	CatExploitedHost:  "Exploited Host",
	CatWebAppAttack:   "Web App Attack",
	CatSSH:            "SSH",
	CatIoTTargeted:    "IoT Targeted",
}
