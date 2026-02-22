package telemetry

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCounter_Basics(t *testing.T) {
	c := NewCounter()
	c.IncProcessed()
	c.AddProcessed(2)
	assert.Equal(t, int64(3), c.Processed())
	assert.Equal(t, int64(3), c.SnapshotAndResetProcessed())
	assert.Equal(t, int64(0), c.Processed())
}

func TestCounter_AddProcessed_IgnoresNonPositive(t *testing.T) {
	c := NewCounter()
	c.AddProcessed(0)
	c.AddProcessed(-10)
	assert.Equal(t, int64(0), c.Processed())
}

func TestCounter_Concurrent(t *testing.T) {
	c := NewCounter()
	const goroutines = 20
	const perG = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				c.IncProcessed()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(goroutines*perG), c.Processed())
}
