package a10

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// TestedACOSVersion records the appliance release used by the project's live
// acceptance test. It is not a pin: every syntactically valid ACOS 6.x.y
// release is accepted by VerifyCompatibility.
const TestedACOSVersion = "6.0.9, build 116"

var acosReleasePattern = regexp.MustCompile(`^\s*(\d+)\.(\d+)\.(\d+)(?:[\s,-]|$)`)

// CompatibilityError reports a malformed or unsupported appliance release.
type CompatibilityError struct {
	SoftwareVersion string
	Reason          string
}

func (err *CompatibilityError) Error() string {
	if strings.TrimSpace(err.SoftwareVersion) == "" {
		return fmt.Sprintf("%v: %s", ErrUnsupportedVersion, err.Reason)
	}
	return fmt.Sprintf("%v %q: %s", ErrUnsupportedVersion, err.SoftwareVersion, err.Reason)
}

func (err *CompatibilityError) Unwrap() error { return ErrUnsupportedVersion }

// VerifyCompatibility checks the supported compatibility contract and returns
// the appliance version that was checked. The contract intentionally accepts
// any ACOS 6.x.y release; patch and build versions are not pinned.
func (s *Session) VerifyCompatibility(ctx context.Context) (VersionInfo, error) {
	version, err := s.ACOSVersion(ctx)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("read ACOS version: %w", err)
	}
	if err := validateCompatibility(version); err != nil {
		return version, err
	}
	return version, nil
}

func validateCompatibility(version VersionInfo) error {
	matches := acosReleasePattern.FindStringSubmatch(version.SoftwareVersion)
	if len(matches) != 4 {
		return &CompatibilityError{
			SoftwareVersion: version.SoftwareVersion,
			Reason:          "expected an ACOS 6.x.y software version",
		}
	}
	major, _ := strconv.Atoi(matches[1])
	if major != 6 {
		return &CompatibilityError{
			SoftwareVersion: version.SoftwareVersion,
			Reason:          "a10-certctl supports ACOS major version 6",
		}
	}
	return nil
}

// VerifyCompatibility authenticates, checks the appliance, and closes the
// temporary session.
func (c *Client) VerifyCompatibility(ctx context.Context) (version VersionInfo, err error) {
	if ctx == nil {
		return version, fmt.Errorf("context must not be nil")
	}
	session, err := c.StartSession(ctx)
	if err != nil {
		return version, err
	}
	defer func() { err = errors.Join(err, session.Close(ctx)) }()
	return session.VerifyCompatibility(ctx)
}
