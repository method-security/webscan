package rfc3961

import (
	"encoding/binary"
	"hash"
)

// Precomputed CRC-32 Table for LSB-first processing (Polynomial: 0xEDB88320)
var crc32Table [256]uint32

func init() {
	const poly = 0xEDB88320 // Reversed polynomial for LSB-first CRC
	for i := range crc32Table {
		crc := uint32(i)
		for j := 0; j < 8; j++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ poly
			} else {
				crc >>= 1
			}
		}
		crc32Table[i] = crc
	}
}

type crc32k struct {
	crc uint32
}

func NewCRC32() hash.Hash {
	return &crc32k{crc: uint32(0)}
}

func (c *crc32k) Reset() {
	c.crc = 0 // // Initial CRC value (not 0xFFFFFFFF as in standard CRC-32)
}

func (c *crc32k) Size() int {
	return 4
}

func (c *crc32k) BlockSize() int {
	return 1
}

func (c *crc32k) Write(data []byte) (int, error) {
	for _, b := range data {
		c.crc = crc32Table[uint8(c.crc)^b] ^ (c.crc >> 8)
	}
	return len(data), nil
}

func (c *crc32k) Sum(b []byte) []byte {
	// Convert to little-endian byte order
	result := make([]byte, 4)
	// // No final ones-complement in Kerberos mod-crc-32
	binary.LittleEndian.PutUint32(result, c.crc)
	return append(b, result...)
}
