package utils

import (
	"fmt"
	"io"
)

// ReadAllLimited reads up to maxBytes from r. Returns error if limit exceeded.
func ReadAllLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	limitedReader := io.LimitReader(r, maxBytes+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("response size exceeds limit of %d bytes", maxBytes)
	}
	return data, nil
}
