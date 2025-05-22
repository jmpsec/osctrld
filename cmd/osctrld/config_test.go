package main


import (
	"testing"
)

func TestLoadConfigurationInvalid(t *testing.T) {
	// Test with invalid file
	_, err := loadConfiguration("invalid", false)
	if err == nil {
		t.Errorf("Expected error, got nil")
	}
}

func TestLoadConfigurationValid(t *testing.T) {
	// Test with valid file
	_, err = loadConfiguration("tests/osctrld-test.json", false)
	if err != nil {
		t.Errorf("Expected nil, got %s", err)
	}
}
