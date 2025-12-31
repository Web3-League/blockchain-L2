package evm

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ripemd160"
)

var (
	ErrPrecompileFailed = errors.New("precompile execution failed")
)

// PrecompiledContract represents a native contract
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64
	Run(input []byte) ([]byte, error)
}

// PrecompiledContracts maps addresses to precompiled contracts
var PrecompiledContracts = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{},
	// 6, 7, 8 are BN256 curves (complex, skip for now)
	common.BytesToAddress([]byte{9}): &blake2F{},
}

// IsPrecompile checks if address is a precompiled contract
func IsPrecompile(addr common.Address) bool {
	_, ok := PrecompiledContracts[addr]
	return ok
}

// RunPrecompile executes a precompiled contract
func RunPrecompile(addr common.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	p, ok := PrecompiledContracts[addr]
	if !ok {
		return nil, gas, ErrPrecompileFailed
	}

	requiredGas := p.RequiredGas(input)
	if gas < requiredGas {
		return nil, 0, ErrOutOfGas
	}

	output, err := p.Run(input)
	return output, gas - requiredGas, err
}

// ============= Precompile Implementations =============

// ecrecover (0x01) - Recover signer from signature
type ecrecover struct{}

func (e *ecrecover) RequiredGas(input []byte) uint64 {
	return 3000
}

func (e *ecrecover) Run(input []byte) ([]byte, error) {
	const ecrecoverInputLength = 128

	input = common.RightPadBytes(input, ecrecoverInputLength)

	// Extract components: hash (32) + v (32) + r (32) + s (32)
	hash := input[0:32]
	v := new(big.Int).SetBytes(input[32:64])
	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])

	// v must be 27 or 28
	if v.Cmp(big.NewInt(27)) < 0 || v.Cmp(big.NewInt(28)) > 0 {
		return nil, nil // Invalid v, return empty (not error)
	}

	// Convert v to 0 or 1
	recoveryID := byte(v.Uint64() - 27)

	// Build signature: r (32) + s (32) + v (1)
	sig := make([]byte, 65)
	copy(sig[0:32], common.LeftPadBytes(r.Bytes(), 32))
	copy(sig[32:64], common.LeftPadBytes(s.Bytes(), 32))
	sig[64] = recoveryID

	// Recover public key
	pubKey, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return nil, nil // Recovery failed, return empty
	}

	// Return address (left-padded to 32 bytes)
	addr := crypto.PubkeyToAddress(*pubKey)
	return common.LeftPadBytes(addr.Bytes(), 32), nil
}

// sha256hash (0x02) - SHA256 hash
type sha256hash struct{}

func (s *sha256hash) RequiredGas(input []byte) uint64 {
	return uint64(60 + 12*((len(input)+31)/32))
}

func (s *sha256hash) Run(input []byte) ([]byte, error) {
	h := sha256.Sum256(input)
	return h[:], nil
}

// ripemd160hash (0x03) - RIPEMD160 hash
type ripemd160hash struct{}

func (r *ripemd160hash) RequiredGas(input []byte) uint64 {
	return uint64(600 + 120*((len(input)+31)/32))
}

func (r *ripemd160hash) Run(input []byte) ([]byte, error) {
	hasher := ripemd160.New()
	hasher.Write(input)
	// Return left-padded to 32 bytes
	return common.LeftPadBytes(hasher.Sum(nil), 32), nil
}

// dataCopy (0x04) - Identity function (returns input as-is)
type dataCopy struct{}

func (d *dataCopy) RequiredGas(input []byte) uint64 {
	return uint64(15 + 3*((len(input)+31)/32))
}

func (d *dataCopy) Run(input []byte) ([]byte, error) {
	return common.CopyBytes(input), nil
}

// bigModExp (0x05) - Modular exponentiation
type bigModExp struct{}

func (b *bigModExp) RequiredGas(input []byte) uint64 {
	// Simplified gas calculation
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	)

	// Basic gas: max(base_len, mod_len)^2 * max(exp_len, 1) / 3
	maxLen := baseLen
	if modLen > maxLen {
		maxLen = modLen
	}
	if maxLen == 0 {
		maxLen = 1
	}

	expLenCalc := expLen
	if expLenCalc == 0 {
		expLenCalc = 1
	}

	gas := (maxLen * maxLen * expLenCalc) / 3
	if gas < 200 {
		gas = 200
	}
	return gas
}

func (b *bigModExp) Run(input []byte) ([]byte, error) {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	)

	if modLen == 0 {
		return nil, nil
	}

	// Extract base, exp, mod
	base := new(big.Int).SetBytes(getData(input, 96, baseLen))
	exp := new(big.Int).SetBytes(getData(input, 96+baseLen, expLen))
	mod := new(big.Int).SetBytes(getData(input, 96+baseLen+expLen, modLen))

	if mod.Sign() == 0 {
		return common.LeftPadBytes(nil, int(modLen)), nil
	}

	// Calculate base^exp mod mod
	result := new(big.Int).Exp(base, exp, mod)
	return common.LeftPadBytes(result.Bytes(), int(modLen)), nil
}

// blake2F (0x09) - BLAKE2b F compression function
type blake2F struct{}

func (b *blake2F) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return 0
	}
	rounds := uint64(input[0])<<24 | uint64(input[1])<<16 | uint64(input[2])<<8 | uint64(input[3])
	return rounds
}

func (b *blake2F) Run(input []byte) ([]byte, error) {
	// Input: rounds (4) + h (64) + m (128) + t (16) + f (1) = 213 bytes
	if len(input) != 213 {
		return nil, ErrPrecompileFailed
	}

	// For now, return zero (full implementation is complex)
	// In production, would implement BLAKE2b F compression
	return make([]byte, 64), nil
}

// ============= Helpers =============

// getData returns a slice from the data based on start and size
func getData(data []byte, start uint64, size uint64) []byte {
	length := uint64(len(data))
	if start >= length {
		return make([]byte, size)
	}
	end := start + size
	if end > length {
		end = length
	}
	result := make([]byte, size)
	copy(result[size-(end-start):], data[start:end])
	return result
}
