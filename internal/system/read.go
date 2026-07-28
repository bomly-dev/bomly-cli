package system

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrInputTooLarge reports that input exceeds a caller-provided size limit.
var ErrInputTooLarge = errors.New("input too large")

const (
	// MaxRepositoryFileBytes is the maximum size of one repository-controlled
	// file parsed in process. The limit is deliberately large enough for
	// monorepo lockfiles while preventing an unbounded allocation.
	MaxRepositoryFileBytes int64 = 64 << 20

	// MaxCacheEntryBytes is the maximum size of one local JSON cache entry.
	// Oversized entries are treated as cache misses by cache callers.
	MaxCacheEntryBytes int64 = 64 << 20
)

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
	file, err := OpenFileLimit(path, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("open bounded file %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", path, err)
	}
	return data, nil
}

// OpenFileLimit opens path for streaming reads and enforces maxBytes before
// opening and while the stream is consumed.
func OpenFileLimit(path string, maxBytes int64) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file %q for bounded read: %w", path, err)
	}
	if info, statErr := file.Stat(); statErr == nil && info.Size() > maxBytes {
		_ = file.Close()
		return nil, fmt.Errorf("read file %q: %w", path, inputTooLargeError(maxBytes))
	}
	return &limitedFileReader{file: file, remaining: maxBytes, maxBytes: maxBytes}, nil
}

// ReadRepositoryFile reads one repository-controlled parser input with the
// shared repository file limit.
func ReadRepositoryFile(path string) ([]byte, error) {
	data, err := ReadFileLimit(path, MaxRepositoryFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read repository file %q: %w", path, err)
	}
	return data, nil
}

// OpenRepositoryFile opens one repository-controlled parser input for a
// streaming read with the shared repository file limit.
func OpenRepositoryFile(path string) (io.ReadCloser, error) {
	reader, err := OpenFileLimit(path, MaxRepositoryFileBytes)
	if err != nil {
		return nil, fmt.Errorf("open repository file %q: %w", path, err)
	}
	return reader, nil
}

// ReadCacheFile reads one local cache entry with the shared cache entry limit.
func ReadCacheFile(path string) ([]byte, error) {
	data, err := ReadFileLimit(path, MaxCacheEntryBytes)
	if err != nil {
		return nil, fmt.Errorf("read cache file %q: %w", path, err)
	}
	return data, nil
}

func inputTooLargeError(maxBytes int64) error {
	return fmt.Errorf("%w: %s limit exceeded", ErrInputTooLarge, ByteLimitLabel(maxBytes))
}

type limitedFileReader struct {
	file      *os.File
	remaining int64
	maxBytes  int64
}

func (r *limitedFileReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.file.Read(probe[:])
		if n > 0 {
			return 0, inputTooLargeError(r.maxBytes)
		}
		return 0, err
	}
	if int64(len(buffer)) > r.remaining {
		buffer = buffer[:r.remaining]
	}
	n, err := r.file.Read(buffer)
	r.remaining -= int64(n)
	return n, err
}

func (r *limitedFileReader) Close() error {
	return r.file.Close()
}
