//go:build !windows

package events

type noopReader struct{}

func NewReader() Reader { return noopReader{} }

func (noopReader) Read() ([]Event, error) { return nil, nil }
