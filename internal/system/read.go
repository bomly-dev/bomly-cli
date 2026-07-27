package system

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrInputTooLarge reports that input exceeds a caller-provided size limit.
var ErrInputTooLarge = errors.New("input too large")

// ByteLimitLabel formats a byte limit for user-facing messages.
func ByteLimitLabel(size int64) string {
	if size > 0 && size%(1<<30) == 0 {
		return fmt.Sprintf("%d GiB", size/(1<<30))
	}
	if size > 0 && size%(1<<20) == 0 {
		return fmt.Sprintf("%d MiB", size/(1<<20))
	}
	if size > 0 && size%(1<<10) == 0 {
		return fmt.Sprintf("%d KiB", size/(1<<10))
	}
	return fmt.Sprintf("%d bytes", size)
}

// ReadLimit reads input while enforcing maxBytes. A negative declaredSize
// means the size is not known before reading.
func ReadLimit(input io.Reader, declaredSize, maxBytes int64) ([]byte, error) {
	if declaredSize > maxBytes {
		return nil, inputTooLargeError(maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(input, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, inputTooLargeError(maxBytes)
	}
	return data, nil
}

// ReadFileLimit reads at most maxBytes from path.
//
// The size is checked before reading when it is available and again while
// reading, so the limit also holds if the file grows after it is opened.
func ReadFileLimit(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		// The *os.PathError already carries the "open <path>" operation
		// context; wrapping again would duplicate it. Callers may keep using
		// errors.Is(err, os.ErrNotExist) on this path.
		return nil, err
	}
	defer func() { _ = file.Close() }()

	declaredSize := int64(-1)
	if info, statErr := file.Stat(); statErr == nil {
		declaredSize = info.Size()
	}
	data, err := ReadLimit(file, declaredSize, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", path, err)
	}
	return data, nil
}

func inputTooLargeError(maxBytes int64) error {
	return fmt.Errorf("%w: %s limit exceeded", ErrInputTooLarge, ByteLimitLabel(maxBytes))
}
