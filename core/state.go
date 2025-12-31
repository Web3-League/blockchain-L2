package core

import (
	"encoding/json"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/syndtr/goleveldb/leveldb"
)

// Account represents an account state
type Account struct {
	Nonce    uint64      `json:"nonce"`
	Balance  *big.Int    `json:"balance"`
	CodeHash common.Hash `json:"codeHash"`
	Code     []byte      `json:"-"`
}

// StateDB manages the world state
type StateDB struct {
	db       *leveldb.DB
	accounts map[common.Address]*Account
	storage  map[common.Address]map[common.Hash]common.Hash
	code     map[common.Hash][]byte
	mu       sync.RWMutex

	// Pending changes for current block
	dirtyAccounts map[common.Address]bool
	dirtyStorage  map[common.Address]map[common.Hash]bool

	// Snapshots for EVM revert
	snapshots []stateSnapshot
	nextSnapID int

	// Self-destructed accounts
	selfDestructed map[common.Address]bool
}

// stateSnapshot stores state for reverting
type stateSnapshot struct {
	id       int
	accounts map[common.Address]*Account
	storage  map[common.Address]map[common.Hash]common.Hash
}

// NewStateDB creates a new state database
func NewStateDB(dbPath string) (*StateDB, error) {
	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, err
	}

	return &StateDB{
		db:             db,
		accounts:       make(map[common.Address]*Account),
		storage:        make(map[common.Address]map[common.Hash]common.Hash),
		code:           make(map[common.Hash][]byte),
		dirtyAccounts:  make(map[common.Address]bool),
		dirtyStorage:   make(map[common.Address]map[common.Hash]bool),
		snapshots:      make([]stateSnapshot, 0),
		selfDestructed: make(map[common.Address]bool),
	}, nil
}

// NewMemoryStateDB creates an in-memory state database (for testing)
func NewMemoryStateDB() *StateDB {
	return &StateDB{
		accounts:       make(map[common.Address]*Account),
		storage:        make(map[common.Address]map[common.Hash]common.Hash),
		code:           make(map[common.Hash][]byte),
		dirtyAccounts:  make(map[common.Address]bool),
		dirtyStorage:   make(map[common.Address]map[common.Hash]bool),
		snapshots:      make([]stateSnapshot, 0),
		selfDestructed: make(map[common.Address]bool),
	}
}

// GetAccount returns an account or creates empty one
func (s *StateDB) GetAccount(addr common.Address) *Account {
	s.mu.RLock()
	acc, exists := s.accounts[addr]
	s.mu.RUnlock()

	if exists {
		return acc
	}

	// Try to load from disk
	if s.db != nil {
		key := append([]byte("account:"), addr.Bytes()...)
		data, err := s.db.Get(key, nil)
		if err == nil {
			acc = &Account{}
			json.Unmarshal(data, acc)
			s.mu.Lock()
			s.accounts[addr] = acc
			s.mu.Unlock()
			return acc
		}
	}

	// Return empty account
	return &Account{
		Nonce:   0,
		Balance: big.NewInt(0),
	}
}

// SetAccount updates an account
func (s *StateDB) SetAccount(addr common.Address, acc *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts[addr] = acc
	s.dirtyAccounts[addr] = true
}

// GetBalance returns the balance of an address
func (s *StateDB) GetBalance(addr common.Address) *big.Int {
	acc := s.GetAccount(addr)
	if acc.Balance == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(acc.Balance)
}

// SetBalance sets the balance of an address
func (s *StateDB) SetBalance(addr common.Address, balance *big.Int) {
	acc := s.GetAccount(addr)
	newAcc := &Account{
		Nonce:    acc.Nonce,
		Balance:  new(big.Int).Set(balance),
		CodeHash: acc.CodeHash,
		Code:     acc.Code,
	}
	s.SetAccount(addr, newAcc)
}

// AddBalance adds to balance
func (s *StateDB) AddBalance(addr common.Address, amount *big.Int) {
	balance := s.GetBalance(addr)
	s.SetBalance(addr, new(big.Int).Add(balance, amount))
}

// SubBalance subtracts from balance
func (s *StateDB) SubBalance(addr common.Address, amount *big.Int) {
	balance := s.GetBalance(addr)
	newBalance := new(big.Int).Sub(balance, amount)
	if newBalance.Sign() < 0 {
		newBalance = big.NewInt(0)
	}
	s.SetBalance(addr, newBalance)
}

// GetNonce returns the nonce of an address
func (s *StateDB) GetNonce(addr common.Address) uint64 {
	return s.GetAccount(addr).Nonce
}

// SetNonce sets the nonce of an address
func (s *StateDB) SetNonce(addr common.Address, nonce uint64) {
	acc := s.GetAccount(addr)
	newAcc := &Account{
		Nonce:    nonce,
		Balance:  acc.Balance,
		CodeHash: acc.CodeHash,
		Code:     acc.Code,
	}
	s.SetAccount(addr, newAcc)
}

// GetCode returns the code of a contract
func (s *StateDB) GetCode(addr common.Address) []byte {
	acc := s.GetAccount(addr)
	if acc.CodeHash == (common.Hash{}) {
		return nil
	}

	s.mu.RLock()
	code, exists := s.code[acc.CodeHash]
	s.mu.RUnlock()

	if exists {
		return code
	}

	// Try disk
	if s.db != nil {
		key := append([]byte("code:"), acc.CodeHash.Bytes()...)
		data, err := s.db.Get(key, nil)
		if err == nil {
			s.mu.Lock()
			s.code[acc.CodeHash] = data
			s.mu.Unlock()
			return data
		}
	}

	return nil
}

// SetCode sets the code of a contract
func (s *StateDB) SetCode(addr common.Address, code []byte) {
	codeHash := crypto.Keccak256Hash(code)

	s.mu.Lock()
	s.code[codeHash] = code
	s.mu.Unlock()

	acc := s.GetAccount(addr)
	newAcc := &Account{
		Nonce:    acc.Nonce,
		Balance:  acc.Balance,
		CodeHash: codeHash,
		Code:     code,
	}
	s.SetAccount(addr, newAcc)
}

// GetCodeHash returns the code hash of a contract
func (s *StateDB) GetCodeHash(addr common.Address) common.Hash {
	return s.GetAccount(addr).CodeHash
}

// GetStorage returns a storage value
func (s *StateDB) GetStorage(addr common.Address, key common.Hash) common.Hash {
	s.mu.RLock()
	if addrStorage, exists := s.storage[addr]; exists {
		if val, ok := addrStorage[key]; ok {
			s.mu.RUnlock()
			return val
		}
	}
	s.mu.RUnlock()

	// Try disk
	if s.db != nil {
		dbKey := append([]byte("storage:"), addr.Bytes()...)
		dbKey = append(dbKey, key.Bytes()...)
		data, err := s.db.Get(dbKey, nil)
		if err == nil {
			return common.BytesToHash(data)
		}
	}

	return common.Hash{}
}

// SetStorage sets a storage value
func (s *StateDB) SetStorage(addr common.Address, key, value common.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.storage[addr] == nil {
		s.storage[addr] = make(map[common.Hash]common.Hash)
	}
	s.storage[addr][key] = value

	if s.dirtyStorage[addr] == nil {
		s.dirtyStorage[addr] = make(map[common.Hash]bool)
	}
	s.dirtyStorage[addr][key] = true
}

// Exist returns true if account exists
func (s *StateDB) Exist(addr common.Address) bool {
	acc := s.GetAccount(addr)
	return acc.Nonce > 0 || (acc.Balance != nil && acc.Balance.Sign() > 0) || acc.CodeHash != (common.Hash{})
}

// Empty returns true if account is empty
func (s *StateDB) Empty(addr common.Address) bool {
	return !s.Exist(addr)
}

// Commit writes all dirty data to disk
func (s *StateDB) Commit() error {
	if s.db == nil {
		// In-memory mode, just clear dirty flags
		s.dirtyAccounts = make(map[common.Address]bool)
		s.dirtyStorage = make(map[common.Address]map[common.Hash]bool)
		return nil
	}

	batch := new(leveldb.Batch)

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Write dirty accounts
	for addr := range s.dirtyAccounts {
		acc := s.accounts[addr]
		data, _ := json.Marshal(acc)
		key := append([]byte("account:"), addr.Bytes()...)
		batch.Put(key, data)

		// Write code if exists
		if acc.CodeHash != (common.Hash{}) {
			if code, exists := s.code[acc.CodeHash]; exists {
				codeKey := append([]byte("code:"), acc.CodeHash.Bytes()...)
				batch.Put(codeKey, code)
			}
		}
	}

	// Write dirty storage
	for addr, keys := range s.dirtyStorage {
		for key := range keys {
			val := s.storage[addr][key]
			dbKey := append([]byte("storage:"), addr.Bytes()...)
			dbKey = append(dbKey, key.Bytes()...)
			batch.Put(dbKey, val.Bytes())
		}
	}

	err := s.db.Write(batch, nil)
	if err != nil {
		return err
	}

	// Clear dirty flags
	s.dirtyAccounts = make(map[common.Address]bool)
	s.dirtyStorage = make(map[common.Address]map[common.Hash]bool)

	return nil
}

// StateRoot computes the state root hash
func (s *StateDB) StateRoot() common.Hash {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Simple state root: hash of all account data
	// In production, use a Merkle Patricia Trie
	var data []byte
	for addr, acc := range s.accounts {
		data = append(data, addr.Bytes()...)
		if acc.Balance != nil {
			data = append(data, acc.Balance.Bytes()...)
		}
		data = append(data, byte(acc.Nonce))
		data = append(data, acc.CodeHash.Bytes()...)
	}

	if len(data) == 0 {
		return common.Hash{}
	}

	return crypto.Keccak256Hash(data)
}

// Copy creates a copy of the state (for EVM execution)
func (s *StateDB) Copy() *StateDB {
	s.mu.RLock()
	defer s.mu.RUnlock()

	newState := NewMemoryStateDB()

	for addr, acc := range s.accounts {
		newAcc := &Account{
			Nonce:    acc.Nonce,
			CodeHash: acc.CodeHash,
		}
		if acc.Balance != nil {
			newAcc.Balance = new(big.Int).Set(acc.Balance)
		}
		newState.accounts[addr] = newAcc
	}

	for addr, storage := range s.storage {
		newState.storage[addr] = make(map[common.Hash]common.Hash)
		for k, v := range storage {
			newState.storage[addr][k] = v
		}
	}

	for hash, code := range s.code {
		newState.code[hash] = code
	}

	return newState
}

// Close closes the database
func (s *StateDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetCodeSize returns the code size of a contract
func (s *StateDB) GetCodeSize(addr common.Address) int {
	code := s.GetCode(addr)
	return len(code)
}

// CreateAccount creates a new account
func (s *StateDB) CreateAccount(addr common.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only create if doesn't exist
	if _, exists := s.accounts[addr]; !exists {
		s.accounts[addr] = &Account{
			Nonce:   0,
			Balance: big.NewInt(0),
		}
		s.dirtyAccounts[addr] = true
	}
}

// SelfDestruct marks an account for destruction
func (s *StateDB) SelfDestruct(addr common.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.selfDestructed[addr] = true

	// Zero out the account
	s.accounts[addr] = &Account{
		Nonce:   0,
		Balance: big.NewInt(0),
	}
	s.dirtyAccounts[addr] = true

	// Clear storage
	delete(s.storage, addr)
}

// HasSelfDestructed returns true if the account is marked for destruction
func (s *StateDB) HasSelfDestructed(addr common.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.selfDestructed[addr]
}

// Snapshot creates a state snapshot and returns its ID
func (s *StateDB) Snapshot() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Copy current state
	snap := stateSnapshot{
		id:       s.nextSnapID,
		accounts: make(map[common.Address]*Account),
		storage:  make(map[common.Address]map[common.Hash]common.Hash),
	}

	for addr, acc := range s.accounts {
		snapAcc := &Account{
			Nonce:    acc.Nonce,
			CodeHash: acc.CodeHash,
		}
		if acc.Balance != nil {
			snapAcc.Balance = new(big.Int).Set(acc.Balance)
		}
		snap.accounts[addr] = snapAcc
	}

	for addr, storage := range s.storage {
		snap.storage[addr] = make(map[common.Hash]common.Hash)
		for k, v := range storage {
			snap.storage[addr][k] = v
		}
	}

	s.snapshots = append(s.snapshots, snap)
	s.nextSnapID++

	return snap.id
}

// RevertToSnapshot reverts state to a previous snapshot
func (s *StateDB) RevertToSnapshot(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find snapshot
	idx := -1
	for i, snap := range s.snapshots {
		if snap.id == id {
			idx = i
			break
		}
	}

	if idx == -1 {
		return // Snapshot not found
	}

	snap := s.snapshots[idx]

	// Restore state
	s.accounts = make(map[common.Address]*Account)
	for addr, acc := range snap.accounts {
		restoredAcc := &Account{
			Nonce:    acc.Nonce,
			CodeHash: acc.CodeHash,
		}
		if acc.Balance != nil {
			restoredAcc.Balance = new(big.Int).Set(acc.Balance)
		}
		s.accounts[addr] = restoredAcc
	}

	s.storage = make(map[common.Address]map[common.Hash]common.Hash)
	for addr, storage := range snap.storage {
		s.storage[addr] = make(map[common.Hash]common.Hash)
		for k, v := range storage {
			s.storage[addr][k] = v
		}
	}

	// Remove this and all later snapshots
	s.snapshots = s.snapshots[:idx]

	// Clear self-destructed
	s.selfDestructed = make(map[common.Address]bool)
}
