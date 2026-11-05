//go:build !linux && !windows

package utils

func getPlatformSerialNumber() (string, error) {
	return "", ErrSerialNumberUnavailable
}
