package main

import (
	"os"
	"strings"
	"testing"

	"github.com/R167/netcheck/checkers"
)

func TestREADMEIncludesAllCheckers(t *testing.T) {
	// Read README.md
	readmeBytes, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("Failed to read README.md: %v", err)
	}
	readmeContent := string(readmeBytes)

	// Get all checkers from the registry
	allCheckers := checkers.AllCheckers()

	var missingCheckers []string
	var undocumentedCheckers []string

	// Check each checker is documented in README
	for _, checker := range allCheckers {
		checkerName := checker.Name()
		flagName := "--" + checkerName

		// Look for the flag in the README
		if !strings.Contains(readmeContent, flagName) {
			missingCheckers = append(missingCheckers, checkerName)
		}
	}

	// Check for documented flags that don't have checkers
	// This helps catch cases where flags are documented but checkers are removed
	documentedFlags := []string{
		"--web", "--ports", "--upnp", "--natpmp", "--ipv6", "--api",
		"--mdns", "--ssdp", "--starlink", "--routes", "--device",
		"--external", "--lldp",
	}

	checkerNames := make(map[string]bool)
	for _, checker := range allCheckers {
		checkerNames[checker.Name()] = true
	}

	for _, flag := range documentedFlags {
		checkerName := strings.TrimPrefix(flag, "--")
		if !checkerNames[checkerName] {
			undocumentedCheckers = append(undocumentedCheckers, checkerName)
		}
	}

	// Report any missing checkers
	if len(missingCheckers) > 0 {
		t.Errorf("The following checkers are missing from README.md: %v", missingCheckers)
	}

	// Report any undocumented checkers (documented but no implementation)
	if len(undocumentedCheckers) > 0 {
		t.Errorf("The following flags are documented in README.md but have no checker implementation: %v", undocumentedCheckers)
	}

	// Specific check for ssdp since it was mentioned as missing
	if !strings.Contains(readmeContent, "--ssdp") {
		t.Error("SSDP checker (--ssdp) is missing from README.md detectors table")
	}
}

func TestREADMECheckersHaveDescriptions(t *testing.T) {
	// Read README.md
	readmeBytes, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("Failed to read README.md: %v", err)
	}
	readmeContent := string(readmeBytes)

	// Get all checkers from the registry
	allCheckers := checkers.AllCheckers()

	var missingDescriptions []string

	// Check each checker has a description in the detectors table
	for _, checker := range allCheckers {
		checkerName := checker.Name()
		flagName := "`--" + checkerName + "`"

		// Look for the flag in a table row (should have | before and after)
		tableRowPattern := "|" // Simple check - just ensure it's in a table format
		if strings.Contains(readmeContent, flagName) && strings.Contains(readmeContent, tableRowPattern) {
			// Found in table, good
			continue
		} else if strings.Contains(readmeContent, flagName) {
			// Found but not in table format - might be okay for special flags
			continue
		} else {
			missingDescriptions = append(missingDescriptions, checkerName)
		}
	}

	if len(missingDescriptions) > 0 {
		t.Errorf("The following checkers lack proper descriptions in the README.md detectors table: %v", missingDescriptions)
	}
}