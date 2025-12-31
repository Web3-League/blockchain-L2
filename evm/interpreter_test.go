package evm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// MockStateDB implements StateDB interface for testing
type MockStateDB struct {
	accounts map[common.Address]*mockAccount
	storage  map[common.Address]map[common.Hash]common.Hash
	code     map[common.Address][]byte
}

type mockAccount struct {
	balance *big.Int
	nonce   uint64
}

func NewMockStateDB() *MockStateDB {
	return &MockStateDB{
		accounts: make(map[common.Address]*mockAccount),
		storage:  make(map[common.Address]map[common.Hash]common.Hash),
		code:     make(map[common.Address][]byte),
	}
}

func (m *MockStateDB) getAccount(addr common.Address) *mockAccount {
	if acc, ok := m.accounts[addr]; ok {
		return acc
	}
	acc := &mockAccount{balance: big.NewInt(0), nonce: 0}
	m.accounts[addr] = acc
	return acc
}

func (m *MockStateDB) GetBalance(addr common.Address) *big.Int {
	return new(big.Int).Set(m.getAccount(addr).balance)
}

func (m *MockStateDB) SetBalance(addr common.Address, amount *big.Int) {
	m.getAccount(addr).balance = new(big.Int).Set(amount)
}

func (m *MockStateDB) AddBalance(addr common.Address, amount *big.Int) {
	acc := m.getAccount(addr)
	acc.balance = new(big.Int).Add(acc.balance, amount)
}

func (m *MockStateDB) SubBalance(addr common.Address, amount *big.Int) {
	acc := m.getAccount(addr)
	acc.balance = new(big.Int).Sub(acc.balance, amount)
}

func (m *MockStateDB) GetNonce(addr common.Address) uint64 {
	return m.getAccount(addr).nonce
}

func (m *MockStateDB) SetNonce(addr common.Address, nonce uint64) {
	m.getAccount(addr).nonce = nonce
}

func (m *MockStateDB) GetCode(addr common.Address) []byte {
	return m.code[addr]
}

func (m *MockStateDB) SetCode(addr common.Address, code []byte) {
	m.code[addr] = code
}

func (m *MockStateDB) GetCodeHash(addr common.Address) common.Hash {
	code := m.code[addr]
	if len(code) == 0 {
		return common.Hash{}
	}
	return common.BytesToHash(code[:32])
}

func (m *MockStateDB) GetCodeSize(addr common.Address) int {
	return len(m.code[addr])
}

func (m *MockStateDB) GetStorage(addr common.Address, key common.Hash) common.Hash {
	if store, ok := m.storage[addr]; ok {
		return store[key]
	}
	return common.Hash{}
}

func (m *MockStateDB) SetStorage(addr common.Address, key, value common.Hash) {
	if m.storage[addr] == nil {
		m.storage[addr] = make(map[common.Hash]common.Hash)
	}
	m.storage[addr][key] = value
}

func (m *MockStateDB) Exist(addr common.Address) bool {
	_, ok := m.accounts[addr]
	return ok
}

func (m *MockStateDB) Empty(addr common.Address) bool {
	return !m.Exist(addr)
}

func (m *MockStateDB) CreateAccount(addr common.Address) {
	m.getAccount(addr)
}

func (m *MockStateDB) SelfDestruct(addr common.Address) {
	delete(m.accounts, addr)
}

func (m *MockStateDB) Snapshot() int {
	return 0
}

func (m *MockStateDB) RevertToSnapshot(int) {}

// Test simple arithmetic
func TestInterpreterAdd(t *testing.T) {
	state := NewMockStateDB()
	ctx := &Context{
		ChainID:     big.NewInt(77702),
		BlockNumber: big.NewInt(1),
		GasPrice:    big.NewInt(1000000000),
		BaseFee:     big.NewInt(1000000000),
		GasLimit:    30000000,
	}

	interpreter := NewInterpreter(state, ctx)

	// Simple bytecode: PUSH1 0x02 PUSH1 0x03 ADD PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
	// 2 + 3 = 5, store in memory, return
	code := []byte{
		byte(PUSH1), 0x02, // push 2
		byte(PUSH1), 0x03, // push 3
		byte(ADD),         // add
		byte(PUSH1), 0x00, // push 0 (offset)
		byte(MSTORE),      // store result at offset 0
		byte(PUSH1), 0x20, // push 32 (size)
		byte(PUSH1), 0x00, // push 0 (offset)
		byte(RETURN),      // return
	}

	contract := &Contract{
		Code:  code,
		Gas:   100000,
		Value: big.NewInt(0),
	}

	result := interpreter.Execute(contract, nil, false)

	if result.Err != nil {
		t.Fatalf("Execution failed: %v", result.Err)
	}

	if len(result.ReturnData) != 32 {
		t.Fatalf("Expected 32 bytes return data, got %d", len(result.ReturnData))
	}

	// Check result (5 as big-endian 32 bytes)
	expected := big.NewInt(5)
	got := new(big.Int).SetBytes(result.ReturnData)
	if got.Cmp(expected) != 0 {
		t.Fatalf("Expected 5, got %s", got.String())
	}

	t.Logf("ADD test passed: 2 + 3 = %s", got.String())
}

// Test storage operations
func TestInterpreterStorage(t *testing.T) {
	state := NewMockStateDB()
	ctx := &Context{
		ChainID:     big.NewInt(77702),
		BlockNumber: big.NewInt(1),
		GasPrice:    big.NewInt(1000000000),
		BaseFee:     big.NewInt(1000000000),
		GasLimit:    30000000,
	}

	interpreter := NewInterpreter(state, ctx)

	contractAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Bytecode: PUSH1 0x42 PUSH1 0x00 SSTORE PUSH1 0x00 SLOAD PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
	// Store 0x42 at slot 0, load it back, return it
	code := []byte{
		byte(PUSH1), 0x42, // push value 0x42
		byte(PUSH1), 0x00, // push key 0
		byte(SSTORE),      // store
		byte(PUSH1), 0x00, // push key 0
		byte(SLOAD),       // load
		byte(PUSH1), 0x00, // push 0 (offset)
		byte(MSTORE),      // store in memory
		byte(PUSH1), 0x20, // push 32 (size)
		byte(PUSH1), 0x00, // push 0 (offset)
		byte(RETURN),      // return
	}

	contract := &Contract{
		Address: contractAddr,
		Code:    code,
		Gas:     100000,
		Value:   big.NewInt(0),
	}

	result := interpreter.Execute(contract, nil, false)

	if result.Err != nil {
		t.Fatalf("Execution failed: %v", result.Err)
	}

	// Check result
	expected := big.NewInt(0x42)
	got := new(big.Int).SetBytes(result.ReturnData)
	if got.Cmp(expected) != 0 {
		t.Fatalf("Expected 0x42, got %s", got.String())
	}

	t.Logf("SSTORE/SLOAD test passed: stored and retrieved %s", got.String())
}

// Test multiplication
func TestInterpreterMul(t *testing.T) {
	state := NewMockStateDB()
	ctx := &Context{
		ChainID:     big.NewInt(77702),
		BlockNumber: big.NewInt(1),
		GasPrice:    big.NewInt(1000000000),
		BaseFee:     big.NewInt(1000000000),
		GasLimit:    30000000,
	}

	interpreter := NewInterpreter(state, ctx)

	// 7 * 6 = 42
	code := []byte{
		byte(PUSH1), 0x07, // push 7
		byte(PUSH1), 0x06, // push 6
		byte(MUL),         // multiply
		byte(PUSH1), 0x00, // push 0 (offset)
		byte(MSTORE),      // store result
		byte(PUSH1), 0x20, // push 32 (size)
		byte(PUSH1), 0x00, // push 0 (offset)
		byte(RETURN),      // return
	}

	contract := &Contract{
		Code:  code,
		Gas:   100000,
		Value: big.NewInt(0),
	}

	result := interpreter.Execute(contract, nil, false)

	if result.Err != nil {
		t.Fatalf("Execution failed: %v", result.Err)
	}

	expected := big.NewInt(42)
	got := new(big.Int).SetBytes(result.ReturnData)
	if got.Cmp(expected) != 0 {
		t.Fatalf("Expected 42, got %s", got.String())
	}

	t.Logf("MUL test passed: 7 * 6 = %s", got.String())
}

// Test CALLDATALOAD
func TestInterpreterCalldata(t *testing.T) {
	state := NewMockStateDB()
	ctx := &Context{
		ChainID:     big.NewInt(77702),
		BlockNumber: big.NewInt(1),
		GasPrice:    big.NewInt(1000000000),
		BaseFee:     big.NewInt(1000000000),
		GasLimit:    30000000,
	}

	interpreter := NewInterpreter(state, ctx)

	// Load first 32 bytes of calldata and return it
	code := []byte{
		byte(PUSH1), 0x00, // push 0 (offset)
		byte(CALLDATALOAD), // load calldata
		byte(PUSH1), 0x00,  // push 0 (offset)
		byte(MSTORE),       // store in memory
		byte(PUSH1), 0x20,  // push 32 (size)
		byte(PUSH1), 0x00,  // push 0 (offset)
		byte(RETURN),       // return
	}

	// Calldata: 0x0000...0099 (99 at the end)
	calldata := make([]byte, 32)
	calldata[31] = 0x99

	contract := &Contract{
		Code:  code,
		Gas:   100000,
		Value: big.NewInt(0),
	}

	result := interpreter.Execute(contract, calldata, false)

	if result.Err != nil {
		t.Fatalf("Execution failed: %v", result.Err)
	}

	expected := big.NewInt(0x99)
	got := new(big.Int).SetBytes(result.ReturnData)
	if got.Cmp(expected) != 0 {
		t.Fatalf("Expected 0x99, got %s", got.String())
	}

	t.Logf("CALLDATALOAD test passed: read %s from calldata", got.String())
}
