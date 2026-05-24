package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIntervalWithJitter(t *testing.T) {
	base := 60 * time.Minute
	min := 54 * time.Minute // base - 10%
	max := 66 * time.Minute // base + 10%

	for i := 0; i < 100; i++ {
		result := intervalWithJitter(base)
		assert.GreaterOrEqual(t, result, min, "jitter should not go below -10%%")
		assert.LessOrEqual(t, result, max, "jitter should not go above +10%%")
	}
}

func TestIntervalWithJitter_SmallInterval(t *testing.T) {
	base := 1 * time.Minute
	min := 54 * time.Second // 1min - 10%
	max := 66 * time.Second // 1min + 10%

	for i := 0; i < 100; i++ {
		result := intervalWithJitter(base)
		assert.GreaterOrEqual(t, result, min)
		assert.LessOrEqual(t, result, max)
	}
}

func TestServiceCommandRegistered(t *testing.T) {
	app := buildApp()
	found := false
	for _, cmd := range app.Commands {
		if cmd.Name == "service" {
			found = true
			assert.Equal(t, "Run as a daemon, periodically syncing flags and certificate", cmd.Usage)
			break
		}
	}
	assert.True(t, found, "service command should be registered")
}
