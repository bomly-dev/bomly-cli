package system

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrFileTooLarge reports that a file exceeds a caller-provided size limit.
var ErrFileTooLarge = errors.New("file exceeds size limit")

// ReadFileLimit reads at most maxBytes from path.
//
// The size is checked before reading when it is available and again while
// reading, so the limit also holds if the file grows after it is opened.
func ReadFileLimit(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	if info, statErr := file.Stat(); statErr == nil && info.Size() > maxBytes {
		return nil, fmt.Errorf("%w: maximum is %d bytes", ErrFileTooLarge, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: maximum is %d bytes", ErrFileTooLarge, maxBytes)
	}
	return data, nil
}
