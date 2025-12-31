package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/syndtr/goleveldb/leveldb"
)

var (
	ErrBlockNotFound = errors.New("block not found")
	ErrInvalidBlock  = errors.New("invalid block")
	ErrInvalidTx     = errors.New("invalid transaction")
)

// Blockchain manages the L2 chain
type Blockchain struct {
	config  *ChainConfig
	db      *leveldb.DB
	state   *StateDB
	genesis *Block

	currentBlock *Block
	blocks       map[common.Hash]*Block
	blocksByNum  map[uint64]*Block
	receipts     map[common.Hash][]*Receipt

	pendingTxs []*Transaction
	txPool     map[common.Hash]*Transaction

	// Withdrawal tracking for L1 bridge
	withdrawals *WithdrawalManager
	l2Bridge    common.Address // L2Bridge contract address

	mu sync.RWMutex

	// Event callbacks
	onNewBlock func(*Block)
}

// NewBlockchain creates a new blockchain
func NewBlockchain(config *ChainConfig, dataDir string) (*Blockchain, error) {
	return NewBlockchainWithGenesis(config, dataDir, nil)
}

// NewBlockchainWithGenesis creates a new blockchain with a custom genesis
func NewBlockchainWithGenesis(config *ChainConfig, dataDir string, genesis *Genesis) (*Blockchain, error) {
	// Open databases
	db, err := leveldb.OpenFile(dataDir+"/chain", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open chain db: %w", err)
	}

	state, err := NewStateDB(dataDir + "/state")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to open state db: %w", err)
	}

	bc := &Blockchain{
		config:      config,
		db:          db,
		state:       state,
		blocks:      make(map[common.Hash]*Block),
		blocksByNum: make(map[uint64]*Block),
		receipts:    make(map[common.Hash][]*Receipt),
		txPool:      make(map[common.Hash]*Transaction),
		withdrawals: NewWithdrawalManager(),
	}

	// Try to load existing chain
	if err := bc.loadChain(); err != nil {
		// Initialize with genesis
		if err := bc.initGenesisWithAlloc(genesis); err != nil {
			return nil, err
		}
	}

	return bc, nil
}

// NewMemoryBlockchain creates an in-memory blockchain (for testing)
func NewMemoryBlockchain(config *ChainConfig) *Blockchain {
	bc := &Blockchain{
		config:      config,
		state:       NewMemoryStateDB(),
		blocks:      make(map[common.Hash]*Block),
		blocksByNum: make(map[uint64]*Block),
		receipts:    make(map[common.Hash][]*Receipt),
		txPool:      make(map[common.Hash]*Transaction),
		withdrawals: NewWithdrawalManager(),
	}

	bc.initGenesisWithAlloc(nil)
	return bc
}

// initGenesisWithAlloc initializes the genesis block with optional custom genesis
func (bc *Blockchain) initGenesisWithAlloc(customGenesis *Genesis) error {
	var genesis *Genesis
	if customGenesis != nil {
		genesis = customGenesis
	} else {
		genesis = DefaultGenesis()
	}
	genesis.Config = bc.config

	// Apply genesis allocations
	for addrHex, alloc := range genesis.Alloc {
		addr := common.HexToAddress(addrHex)
		balance, _ := new(big.Int).SetString(alloc.Balance, 10)
		bc.state.SetBalance(addr, balance)
		if alloc.Code != "" {
			bc.state.SetCode(addr, HexToBytes(alloc.Code))
		}
		if alloc.Nonce > 0 {
			bc.state.SetNonce(addr, alloc.Nonce)
		}
	}

	// Create genesis block
	header := &BlockHeader{
		ParentHash: common.Hash{},
		Coinbase:   common.Address{},
		StateRoot:  bc.state.StateRoot(),
		TxRoot:     common.Hash{},
		Number:     big.NewInt(0),
		GasLimit:   genesis.GasLimit,
		GasUsed:    0,
		Timestamp:  genesis.Timestamp,
		ExtraData:  []byte("NanoPy Turbo Genesis"),
	}

	bc.genesis = NewBlock(header, nil)
	bc.currentBlock = bc.genesis
	bc.blocks[bc.genesis.Hash()] = bc.genesis
	bc.blocksByNum[0] = bc.genesis

	bc.state.Commit()
	bc.saveBlock(bc.genesis)

	return nil
}

// loadChain loads the chain from disk
func (bc *Blockchain) loadChain() error {
	if bc.db == nil {
		return errors.New("no database")
	}

	// Load current block number
	data, err := bc.db.Get([]byte("currentBlock"), nil)
	if err != nil {
		return err
	}

	blockHash := common.BytesToHash(data)
	block, err := bc.loadBlock(blockHash)
	if err != nil {
		return err
	}

	bc.currentBlock = block

	// Load genesis
	genesisData, err := bc.db.Get([]byte("block:0"), nil)
	if err != nil {
		return err
	}
	bc.genesis = &Block{}
	json.Unmarshal(genesisData, bc.genesis)
	bc.blocks[bc.genesis.Hash()] = bc.genesis
	bc.blocksByNum[0] = bc.genesis

	return nil
}

// loadBlock loads a block from disk
func (bc *Blockchain) loadBlock(hash common.Hash) (*Block, error) {
	key := append([]byte("block:"), hash.Bytes()...)
	data, err := bc.db.Get(key, nil)
	if err != nil {
		return nil, ErrBlockNotFound
	}

	block := &Block{}
	if err := json.Unmarshal(data, block); err != nil {
		return nil, err
	}

	bc.mu.Lock()
	bc.blocks[hash] = block
	bc.blocksByNum[block.Number().Uint64()] = block
	bc.mu.Unlock()

	return block, nil
}

// saveBlock saves a block to disk
func (bc *Blockchain) saveBlock(block *Block) error {
	if bc.db == nil {
		return nil // In-memory mode
	}

	data, err := json.Marshal(block)
	if err != nil {
		return err
	}

	batch := new(leveldb.Batch)

	// Save by hash
	key := append([]byte("block:"), block.Hash().Bytes()...)
	batch.Put(key, data)

	// Save by number
	numKey := fmt.Sprintf("block:%d", block.Number().Uint64())
	batch.Put([]byte(numKey), data)

	// Update current block
	batch.Put([]byte("currentBlock"), block.Hash().Bytes())

	return bc.db.Write(batch, nil)
}

// CurrentBlock returns the current block
func (bc *Blockchain) CurrentBlock() *Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.currentBlock
}

// GetBlock returns a block by hash
func (bc *Blockchain) GetBlock(hash common.Hash) *Block {
	bc.mu.RLock()
	block, exists := bc.blocks[hash]
	bc.mu.RUnlock()

	if exists {
		return block
	}

	// Try disk
	block, _ = bc.loadBlock(hash)
	return block
}

// GetBlockByNumber returns a block by number
func (bc *Blockchain) GetBlockByNumber(num uint64) *Block {
	bc.mu.RLock()
	block, exists := bc.blocksByNum[num]
	bc.mu.RUnlock()

	if exists {
		return block
	}

	// Try disk
	if bc.db != nil {
		key := fmt.Sprintf("block:%d", num)
		data, err := bc.db.Get([]byte(key), nil)
		if err == nil {
			block := &Block{}
			json.Unmarshal(data, block)
			bc.mu.Lock()
			bc.blocks[block.Hash()] = block
			bc.blocksByNum[num] = block
			bc.mu.Unlock()
			return block
		}
	}

	return nil
}

// State returns the state database
func (bc *Blockchain) State() *StateDB {
	return bc.state
}

// Config returns the chain config
func (bc *Blockchain) Config() *ChainConfig {
	return bc.config
}

// AddTransaction adds a transaction to the pending pool
func (bc *Blockchain) AddTransaction(tx *Transaction) error {
	// Validate transaction
	if err := bc.validateTx(tx); err != nil {
		return err
	}

	bc.mu.Lock()
	defer bc.mu.Unlock()

	bc.pendingTxs = append(bc.pendingTxs, tx)
	bc.txPool[tx.Hash()] = tx

	return nil
}

// validateTx validates a transaction
func (bc *Blockchain) validateTx(tx *Transaction) error {
	from := tx.From()
	if from == (common.Address{}) {
		return errors.New("invalid sender")
	}

	// Check nonce
	nonce := bc.state.GetNonce(from)
	if tx.Nonce < nonce {
		return errors.New("nonce too low")
	}

	// Check balance
	cost := new(big.Int).Mul(tx.GasPrice, big.NewInt(int64(tx.GasLimit)))
	cost.Add(cost, tx.Value)
	if bc.state.GetBalance(from).Cmp(cost) < 0 {
		return errors.New("insufficient balance")
	}

	return nil
}

// GetPendingTransactions returns pending transactions
func (bc *Blockchain) GetPendingTransactions() []*Transaction {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	txs := make([]*Transaction, len(bc.pendingTxs))
	copy(txs, bc.pendingTxs)
	return txs
}

// GetTransaction returns a transaction by hash
func (bc *Blockchain) GetTransaction(hash common.Hash) *Transaction {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.txPool[hash]
}

// GetReceipts returns receipts for a block
func (bc *Blockchain) GetReceipts(blockHash common.Hash) []*Receipt {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.receipts[blockHash]
}

// GetReceipt returns a receipt by tx hash
func (bc *Blockchain) GetReceipt(txHash common.Hash) *Receipt {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	for _, receipts := range bc.receipts {
		for _, r := range receipts {
			if r.TxHash == txHash {
				return r
			}
		}
	}
	return nil
}

// ProduceBlock creates a new block from pending transactions
func (bc *Blockchain) ProduceBlock(coinbase common.Address) (*Block, []*Receipt, error) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	parent := bc.currentBlock
	blockNum := new(big.Int).Add(parent.Number(), big.NewInt(1))

	// Execute transactions
	var receipts []*Receipt
	var includedTxs []*Transaction
	var gasUsed uint64

	for _, tx := range bc.pendingTxs {
		if gasUsed+tx.GasLimit > bc.config.BlockTime*1000000 { // rough gas limit
			break
		}

		receipt, err := bc.executeTx(tx, blockNum.Uint64(), len(includedTxs))
		if err != nil {
			continue // Skip failed tx
		}

		includedTxs = append(includedTxs, tx)
		receipts = append(receipts, receipt)
		gasUsed += receipt.GasUsed
	}

	// Create block header
	header := &BlockHeader{
		ParentHash:  parent.Hash(),
		Coinbase:    coinbase,
		StateRoot:   bc.state.StateRoot(),
		TxRoot:      bc.computeTxRoot(includedTxs),
		ReceiptRoot: bc.computeReceiptRoot(receipts),
		Number:      blockNum,
		GasLimit:    30000000,
		GasUsed:     gasUsed,
		Timestamp:   uint64(time.Now().Unix()),
		ExtraData:   []byte("NanoPy Turbo"),
	}

	block := NewBlock(header, includedTxs)

	// Update chain
	bc.blocks[block.Hash()] = block
	bc.blocksByNum[blockNum.Uint64()] = block
	bc.currentBlock = block
	bc.receipts[block.Hash()] = receipts

	// Clear included txs from pending
	bc.pendingTxs = bc.pendingTxs[len(includedTxs):]
	for _, tx := range includedTxs {
		delete(bc.txPool, tx.Hash())
	}

	// Commit state
	bc.state.Commit()
	bc.saveBlock(block)

	// Process withdrawal events from L2Bridge
	bc.processWithdrawalLogs(receipts, blockNum.Uint64())

	// Callback
	if bc.onNewBlock != nil {
		go bc.onNewBlock(block)
	}

	return block, receipts, nil
}

// executeTx executes a single transaction using the TurboEVM
func (bc *Blockchain) executeTx(tx *Transaction, blockNum uint64, txIndex int) (*Receipt, error) {
	// Create a temporary header for EVM context
	header := &BlockHeader{
		Number:    big.NewInt(int64(blockNum)),
		Timestamp: uint64(time.Now().Unix()),
		GasLimit:  30000000,
	}

	// Use the full EVM execution from evm.go
	receipt, err := ExecuteTransaction(bc, tx, header, bc.currentBlock.Header.Coinbase)
	if err != nil {
		return nil, err
	}

	// Set transaction index
	receipt.TransactionIdx = uint64(txIndex)

	return receipt, nil
}

// computeTxRoot computes the transactions root
func (bc *Blockchain) computeTxRoot(txs []*Transaction) common.Hash {
	if len(txs) == 0 {
		return common.Hash{}
	}
	var data []byte
	for _, tx := range txs {
		data = append(data, tx.Hash().Bytes()...)
	}
	return crypto.Keccak256Hash(data)
}

// computeReceiptRoot computes the receipts root
func (bc *Blockchain) computeReceiptRoot(receipts []*Receipt) common.Hash {
	if len(receipts) == 0 {
		return common.Hash{}
	}
	var data []byte
	for _, r := range receipts {
		data = append(data, r.TxHash.Bytes()...)
	}
	return crypto.Keccak256Hash(data)
}

// OnNewBlock sets the callback for new blocks
func (bc *Blockchain) OnNewBlock(callback func(*Block)) {
	bc.onNewBlock = callback
}

// Close closes the blockchain
func (bc *Blockchain) Close() error {
	if bc.db != nil {
		bc.db.Close()
	}
	return bc.state.Close()
}

// SetL2Bridge sets the L2Bridge contract address for withdrawal tracking
func (bc *Blockchain) SetL2Bridge(addr common.Address) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.l2Bridge = addr
}

// GetL2Bridge returns the L2Bridge contract address
func (bc *Blockchain) GetL2Bridge() common.Address {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.l2Bridge
}

// WithdrawalManager returns the withdrawal manager
func (bc *Blockchain) WithdrawalManager() *WithdrawalManager {
	return bc.withdrawals
}

// WithdrawalInitiated event signature: keccak256("WithdrawalInitiated(address,uint256,uint256)")
var WithdrawalInitiatedTopic = crypto.Keccak256Hash([]byte("WithdrawalInitiated(address,uint256,uint256)"))

// processWithdrawalLogs checks receipts for withdrawal events from L2Bridge
func (bc *Blockchain) processWithdrawalLogs(receipts []*Receipt, blockNum uint64) {
	if bc.l2Bridge == (common.Address{}) {
		return // L2Bridge not set
	}

	for _, receipt := range receipts {
		if receipt.Status != 1 {
			continue // Skip failed transactions
		}

		for _, log := range receipt.Logs {
			// Check if this is from L2Bridge and is a WithdrawalInitiated event
			if log.Address != bc.l2Bridge {
				continue
			}
			if len(log.Topics) < 1 || log.Topics[0] != WithdrawalInitiatedTopic {
				continue
			}

			// Parse withdrawal event: WithdrawalInitiated(address indexed recipient, uint256 amount, uint256 withdrawalIndex)
			// Topics[0] = event signature
			// Topics[1] = recipient (indexed)
			// Data = amount (32 bytes) + withdrawalIndex (32 bytes)
			if len(log.Topics) < 2 || len(log.Data) < 64 {
				continue
			}

			recipient := common.BytesToAddress(log.Topics[1].Bytes())
			amount := new(big.Int).SetBytes(log.Data[:32])
			// withdrawalIndex is in the next 32 bytes (but we assign our own)

			// Add to withdrawal manager
			bc.withdrawals.AddWithdrawal(recipient, amount, blockNum, receipt.TxHash)
		}
	}
}

// GetWithdrawalProof returns the Merkle proof for a withdrawal
func (bc *Blockchain) GetWithdrawalProof(withdrawalIndex uint64) ([]common.Hash, common.Hash, *Withdrawal, error) {
	proof, root, err := bc.withdrawals.GetMerkleProof(withdrawalIndex)
	if err != nil {
		return nil, common.Hash{}, nil, err
	}

	withdrawal := bc.withdrawals.GetWithdrawal(withdrawalIndex)
	return proof, root, withdrawal, nil
}

// GetWithdrawalRoot returns the current withdrawal Merkle root
func (bc *Blockchain) GetWithdrawalRoot() common.Hash {
	_, root := bc.withdrawals.BuildMerkleTree()
	return root
}

// GetPendingWithdrawals returns all pending withdrawals
func (bc *Blockchain) GetPendingWithdrawals() []*Withdrawal {
	return bc.withdrawals.GetPendingWithdrawals()
}
