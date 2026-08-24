package a10

import "errors"

// Stable error categories support errors.Is without coupling callers to
// concrete aXAPI response types or status-code handling.
var (
	ErrAuthentication     = errors.New("A10 authentication failed")
	ErrNotFound           = errors.New("A10 object not found")
	ErrConflict           = errors.New("A10 configuration conflict")
	ErrUnsupportedVersion = errors.New("unsupported ACOS version")
	ErrAmbiguousState     = errors.New("A10 operation result is ambiguous")
)
