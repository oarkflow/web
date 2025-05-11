package hash

import (
	"unsafe"
)

// Bytes hashes the given byte slice.
func Bytes(in []byte) uint64 {
	i := 0
	x := uint64(0)

	// Cache lines on modern processors are 64 bytes long.
	// A single uint64 consumes 8 bytes.
	// That means we should read 8 uint64 at a time.
	for ; i < len(in)-63; i += 64 {
		words := (*[8]uint64)(unsafe.Pointer(&in[i]))
		x = mix(x, words[0])
		x = mix(x, words[1])
		x = mix(x, words[2])
		x = mix(x, words[3])
		x = mix(x, words[4])
		x = mix(x, words[5])
		x = mix(x, words[6])
		x = mix(x, words[7])
	}

	// While we have at least 8 bytes left, convert them to uint64.
	for ; i < len(in)-7; i += 8 {
		word := *(*uint64)(unsafe.Pointer(&in[i]))
		x = mix(x, word)
	}

	// Hash the remaining bytes.
	if i < len(in) {
		word := uint64(0)

		for ; i < len(in); i++ {
			word = (word << 8) | uint64(in[i])
		}

		x = mix(x, word)
	}

	// This helps to avoid clashes between different lengths
	// of all-zero bytes by making the data length significant.
	x = mix(x, uint64(len(in)))

	return x
}

func mix(x uint64, b uint64) uint64 {
	return (x + b) * 0x9E3779B97F4A7C15
}
