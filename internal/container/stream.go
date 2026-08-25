package container

import (
	"bytes"
	"fmt"
	"io"
)

// Write writes the fixed header followed by payload to dst (streaming).
func Write(dst io.Writer, h Header, payload io.Reader) error {
	hdr, err := Marshal(h)
	if err != nil {
		return err
	}
	if _, err := dst.Write(hdr); err != nil {
		return fmt.Errorf("container header write: %w", err)
	}
	if _, err := io.Copy(dst, payload); err != nil {
		return fmt.Errorf("container payload write: %w", err)
	}
	return nil
}

// Unwrap peeks at src. If it is an S3VCTR01 object, returns the parsed header
// and a reader positioned at the payload. Otherwise returns isContainer=false
// and a reader that restores the peeked bytes (legacy objects).
func Unwrap(src io.Reader) (hdr Header, payload io.Reader, isContainer bool, err error) {
	head := make([]byte, HeaderSize)
	n, readErr := io.ReadFull(src, head)
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		return Header{}, nil, false, fmt.Errorf("container peek: %w", readErr)
	}
	restored := io.MultiReader(bytes.NewReader(head[:n]), src)
	if n < len(Magic) || !IsMagic(head[:n]) {
		return Header{}, restored, false, nil
	}
	if n < HeaderSize {
		return Header{}, nil, false, fmt.Errorf("%w: truncated header", ErrCorruptHeader)
	}
	h, err := Parse(head)
	if err != nil {
		return Header{}, nil, false, err
	}
	return h, src, true, nil
}
