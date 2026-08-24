package a10

import (
	"errors"
	"testing"
)

func TestCompatibilityAcceptsEveryACOS6PatchVersion(t *testing.T) {
	for _, value := range []string{
		"6.0.0",
		"6.0.9, build 116 (Jul-20-2026,09:38)",
		"6.9.42-P7",
	} {
		if err := validateCompatibility(VersionInfo{SoftwareVersion: value}); err != nil {
			t.Errorf("ACOS release %q was rejected: %v", value, err)
		}
	}
}

func TestCompatibilityRejectsOtherOrMalformedReleases(t *testing.T) {
	for _, value := range []string{"", "6", "6.0", "6.0.9.1", "5.2.1", "7.0.0", "release-6.0.9"} {
		err := validateCompatibility(VersionInfo{SoftwareVersion: value})
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("ACOS release %q returned %v, want ErrUnsupportedVersion", value, err)
		}
	}
}
