package evm

import (
	"math/big"
)

const (
	// MaxStackSize is the maximum EVM stack size
	MaxStackSize = 1024
)

// Stack represents the EVM stack
type Stack struct {
	data []*big.Int
}

// NewStack creates a new stack
func NewStack() *Stack {
	return &Stack{
		data: make([]*big.Int, 0, 16),
	}
}

// Push pushes a value onto the stack
func (s *Stack) Push(val *big.Int) {
	if val == nil {
		val = big.NewInt(0)
	}
	s.data = append(s.data, new(big.Int).Set(val))
}

// PushBytes pushes bytes as a big.Int
func (s *Stack) PushBytes(b []byte) {
	s.Push(new(big.Int).SetBytes(b))
}

// Pop removes and returns the top element
func (s *Stack) Pop() *big.Int {
	if len(s.data) == 0 {
		return big.NewInt(0)
	}
	val := s.data[len(s.data)-1]
	s.data = s.data[:len(s.data)-1]
	return val
}

// Peek returns the top element without removing it
func (s *Stack) Peek() *big.Int {
	if len(s.data) == 0 {
		return big.NewInt(0)
	}
	return s.data[len(s.data)-1]
}

// PeekN returns the nth element from top (0 = top)
func (s *Stack) PeekN(n int) *big.Int {
	if n >= len(s.data) {
		return big.NewInt(0)
	}
	return s.data[len(s.data)-1-n]
}

// Swap swaps the top element with the nth element
func (s *Stack) Swap(n int) error {
	if n >= len(s.data) {
		return ErrStackUnderflow
	}
	top := len(s.data) - 1
	s.data[top], s.data[top-n] = s.data[top-n], s.data[top]
	return nil
}

// Dup duplicates the nth element to the top
func (s *Stack) Dup(n int) error {
	if n > len(s.data) {
		return ErrStackUnderflow
	}
	if len(s.data) >= MaxStackSize {
		return ErrStackOverflow
	}
	val := s.data[len(s.data)-1-n]
	s.data = append(s.data, new(big.Int).Set(val))
	return nil
}

// Len returns the stack length
func (s *Stack) Len() int {
	return len(s.data)
}

// Back returns elements from the back (0 = top)
func (s *Stack) Back(n int) *big.Int {
	if n >= len(s.data) {
		return nil
	}
	return s.data[len(s.data)-1-n]
}

// Data returns the underlying data
func (s *Stack) Data() []*big.Int {
	return s.data
}
