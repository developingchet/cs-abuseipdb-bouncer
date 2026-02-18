package abuseipdb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCategoryConstants(t *testing.T) {
	// Verify the numeric values match the AbuseIPDB API specification.
	assert.Equal(t, 1, CatDNSCompromise)
	assert.Equal(t, 2, CatDNSPoisoning)
	assert.Equal(t, 3, CatFraudOrders)
	assert.Equal(t, 4, CatDDoSAttack)
	assert.Equal(t, 5, CatFTPBruteForce)
	assert.Equal(t, 6, CatPingOfDeath)
	assert.Equal(t, 7, CatPhishing)
	assert.Equal(t, 8, CatFraudVoIP)
	assert.Equal(t, 9, CatOpenProxy)
	assert.Equal(t, 10, CatWebSpam)
	assert.Equal(t, 11, CatEmailSpam)
	assert.Equal(t, 12, CatBlogSpam)
	assert.Equal(t, 13, CatVPNIP)
	assert.Equal(t, 14, CatPortScan)
	assert.Equal(t, 15, CatHacking)
	assert.Equal(t, 16, CatSQLInjection)
	assert.Equal(t, 17, CatSpoofing)
	assert.Equal(t, 18, CatBruteForce)
	assert.Equal(t, 19, CatBadWebBot)
	assert.Equal(t, 20, CatExploitedHost)
	assert.Equal(t, 21, CatWebAppAttack)
	assert.Equal(t, 22, CatSSH)
	assert.Equal(t, 23, CatIoTTargeted)
}

func TestCategoryNameMap(t *testing.T) {
	// Every constant must have a display name.
	ids := []int{
		CatDNSCompromise, CatDNSPoisoning, CatFraudOrders, CatDDoSAttack,
		CatFTPBruteForce, CatPingOfDeath, CatPhishing, CatFraudVoIP,
		CatOpenProxy, CatWebSpam, CatEmailSpam, CatBlogSpam, CatVPNIP,
		CatPortScan, CatHacking, CatSQLInjection, CatSpoofing, CatBruteForce,
		CatBadWebBot, CatExploitedHost, CatWebAppAttack, CatSSH, CatIoTTargeted,
	}

	for _, id := range ids {
		name, ok := CategoryName[id]
		assert.True(t, ok, "category %d has no display name", id)
		assert.NotEmpty(t, name, "category %d has empty display name", id)
	}

	// Map must have exactly 23 entries -- one per defined category.
	assert.Equal(t, 23, len(CategoryName))
}

func TestCategoryNameValues(t *testing.T) {
	assert.Equal(t, "DNS Compromise", CategoryName[CatDNSCompromise])
	assert.Equal(t, "SSH", CategoryName[CatSSH])
	assert.Equal(t, "Hacking", CategoryName[CatHacking])
	assert.Equal(t, "Brute-Force", CategoryName[CatBruteForce])
	assert.Equal(t, "Web App Attack", CategoryName[CatWebAppAttack])
}
