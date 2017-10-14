package common

import "bytes"

// NullTerminatedString finds the null-terminator in the given slice and returns
// a string containing the data before the null-terminator.
func NullTerminatedString(data []byte) string {
	nullTerm := bytes.IndexByte(data, 0)
	if nullTerm == -1 {
		return string(data)
	}
	return string(data[:nullTerm])
}
