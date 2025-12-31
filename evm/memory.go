package evm

import (
	"math/big"
)

// Memory represents EVM memory
type Memory struct {
	store []byte
}

// NewMemory creates a new memory instance
func NewMemory() *Memory {
	return &Memory{
		store: make([]byte, 0, 4096),
	}
}

// Set stores a value at offset
func (m *Memory) Set(offset, size uint64, value []byte) {
	if size == 0 {
		return
	}

	// Expand if needed
	if offset+size > uint64(len(m.store)) {
		m.Resize(offset + size)
	}

	copy(m.store[offset:offset+size], value)
}

// Set32 stores a 32-byte value at offset
func (m *Memory) Set32(offset uint64, val *big.Int) {
	if offset+32 > uint64(len(m.store)) {
		m.Resize(offset + 32)
	}

	// Zero the destination
	for i := uint64(0); i < 32; i++ {
		m.store[offset+i] = 0
	}

	// Copy value (right-aligned)
	b := val.Bytes()
	copy(m.store[offset+32-uint64(len(b)):offset+32], b)
}

// SetByte stores a single byte at offset
func (m *Memory) SetByte(offset uint64, val byte) {
	if offset >= uint64(len(m.store)) {
		m.Resize(offset + 1)
	}
	m.store[offset] = val
}

// Get returns a slice of memory
func (m *Memory) Get(offset, size uint64) []byte {
	if size == 0 {
		return nil
	}

	if offset+size > uint64(len(m.store)) {
		m.Resize(offset + size)
	}

	return m.store[offset : offset+size]
}

// GetCopy returns a copy of a slice of memory
func (m *Memory) GetCopy(offset, size uint64) []byte {
	if size == 0 {
		return nil
	}

	if offset+size > uint64(len(m.store)) {
		m.Resize(offset + size)
	}

	cpy := make([]byte, size)
	copy(cpy, m.store[offset:offset+size])
	return cpy
}

// GetPtr returns a pointer to the memory slice
func (m *Memory) GetPtr(offset, size uint64) []byte {
	if size == 0 {
		return nil
	}

	if offset+size > uint64(len(m.store)) {
		m.Resize(offset + size)
	}

	return m.store[offset : offset+size]
}

// Resize expands the memory to size bytes
func (m *Memory) Resize(size uint64) {
	// Round up to 32-byte words
	size = (size + 31) / 32 * 32

	if uint64(len(m.store)) < size {
		newStore := make([]byte, size)
		copy(newStore, m.store)
		m.store = newStore
	}
}

// Len returns the current memory size
func (m *Memory) Len() uint64 {
	return uint64(len(m.store))
}

// Data returns the underlying data
func (m *Memory) Data() []byte {
	return m.store
}

// Copy copies memory from src to dst
func (m *Memory) Copy(dst, src, size uint64) {
	if size == 0 {
		return
	}

	// Expand if needed
	maxOffset := dst + size
	if src+size > maxOffset {
		maxOffset = src + size
	}
	if maxOffset > uint64(len(m.store)) {
		m.Resize(maxOffset)
	}

	copy(m.store[dst:dst+size], m.store[src:src+size])
}

// CalcMemoryCost calculates the gas cost for memory expansion
func CalcMemoryCost(currentSize, newSize uint64) uint64 {
	if newSize <= currentSize {
		return 0
	}

	// Round up to 32-byte words
	newWords := (newSize + 31) / 32
	currentWords := (currentSize + 31) / 32

	if newWords <= currentWords {
		return 0
	}

	// memory_cost = (memory_size_word ** 2) / 512 + (3 * memory_size_word)
	newCost := (newWords*newWords)/512 + 3*newWords
	currentCost := (currentWords*currentWords)/512 + 3*currentWords

	return newCost - currentCost
}
