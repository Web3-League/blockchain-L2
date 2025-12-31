package sequencer

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/nanopy/nanopy-turbo/core"
)

// Sequencer produces blocks for the L2
type Sequencer struct {
	bc        *core.Blockchain
	coinbase  common.Address
	blockTime time.Duration
	running   bool
	stopCh    chan struct{}

	// L1 connection for state root submission
	l1RPC        string
	l1Bridge     common.Address
	sequencerKey *ecdsa.PrivateKey

	// Callbacks
	onBlock func(*core.Block)
}

// Config holds sequencer configuration
type Config struct {
	Coinbase     common.Address
	BlockTime    time.Duration
	L1RPC        string
	L1Bridge     common.Address
	SequencerKey *ecdsa.PrivateKey
}

// NewSequencer creates a new sequencer
func NewSequencer(bc *core.Blockchain, config *Config) *Sequencer {
	return &Sequencer{
		bc:           bc,
		coinbase:     config.Coinbase,
		blockTime:    config.BlockTime,
		l1RPC:        config.L1RPC,
		l1Bridge:     config.L1Bridge,
		sequencerKey: config.SequencerKey,
		stopCh:       make(chan struct{}),
	}
}

// Start starts the sequencer
func (s *Sequencer) Start() {
	if s.running {
		return
	}
	s.running = true

	log.Printf("Sequencer started (block time: %v)", s.blockTime)
	log.Printf("Coinbase: %s", s.coinbase.Hex())
	if s.l1RPC != "" {
		log.Printf("L1 RPC: %s", s.l1RPC)
		log.Printf("L1 Bridge: %s", s.l1Bridge.Hex())
	}

	go s.loop()
}

// Stop stops the sequencer
func (s *Sequencer) Stop() {
	if !s.running {
		return
	}
	s.running = false
	close(s.stopCh)
	log.Println("Sequencer stopped")
}

// loop is the main sequencer loop
func (s *Sequencer) loop() {
	ticker := time.NewTicker(s.blockTime)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.produceBlock()
		case <-s.stopCh:
			return
		}
	}
}

// produceBlock produces a new block
func (s *Sequencer) produceBlock() {
	pendingTxs := s.bc.GetPendingTransactions()

	// Only produce block if there are transactions or it's been a while
	if len(pendingTxs) == 0 {
		// Still produce empty blocks periodically for liveness
		currentBlock := s.bc.CurrentBlock()
		if time.Since(time.Unix(int64(currentBlock.Header.Timestamp), 0)) < s.blockTime*5 {
			return
		}
	}

	block, receipts, err := s.bc.ProduceBlock(s.coinbase)
	if err != nil {
		log.Printf("Failed to produce block: %v", err)
		return
	}

	log.Printf("Produced block #%d with %d txs (gas used: %d)",
		block.Number().Uint64(),
		len(block.Transactions),
		block.Header.GasUsed,
	)

	// Submit state root to L1 (every 10 blocks)
	if block.Number().Uint64()%10 == 0 && s.l1RPC != "" && s.l1Bridge != (common.Address{}) {
		go s.submitStateRoot(block)
	}

	// Callback
	if s.onBlock != nil {
		s.onBlock(block)
	}

	_ = receipts
}

// submitStateRoot submits the state root to L1
func (s *Sequencer) submitStateRoot(block *core.Block) {
	if s.l1RPC == "" {
		return
	}

	stateRoot := block.Header.StateRoot
	blockNum := block.Number().Uint64()

	log.Printf("Submitting state root to L1: block=%d root=%s",
		blockNum,
		stateRoot.Hex(),
	)

	// Build calldata for submitStateRoot(uint256, bytes32)
	// Function selector: keccak256("submitStateRoot(uint256,bytes32)")[:4]
	funcSelector := crypto.Keccak256([]byte("submitStateRoot(uint256,bytes32)"))[:4]

	// Encode parameters
	blockNumBytes := common.LeftPadBytes(big.NewInt(int64(blockNum)).Bytes(), 32)
	stateRootBytes := stateRoot.Bytes()

	calldata := append(funcSelector, blockNumBytes...)
	calldata = append(calldata, stateRootBytes...)

	// Sign and send transaction to L1 Bridge
	err := s.sendL1Transaction(s.l1Bridge, calldata, big.NewInt(0))
	if err != nil {
		log.Printf("Failed to submit state root to L1: %v", err)
	} else {
		log.Printf("State root submitted to L1 successfully")
	}
}

// getL1Nonce gets the current nonce from L1
func (s *Sequencer) getL1Nonce() (uint64, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionCount",
		"params":  []interface{}{s.coinbase.Hex(), "latest"},
		"id":      1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return 0, err
	}

	resp, err := http.Post(s.l1RPC, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	// Parse hex result
	var nonce uint64
	if len(result.Result) > 2 {
		nonceBytes, _ := hex.DecodeString(result.Result[2:])
		nonce = new(big.Int).SetBytes(nonceBytes).Uint64()
	}

	return nonce, nil
}

// sendL1Transaction signs and sends a transaction to L1
func (s *Sequencer) sendL1Transaction(to common.Address, data []byte, value *big.Int) error {
	if s.sequencerKey == nil {
		return s.sendL1TransactionUnsigned(to, data, value)
	}

	// Get nonce
	nonce, err := s.getL1Nonce()
	if err != nil {
		return err
	}

	// Get gas price from L1
	gasPrice, err := s.getL1GasPrice()
	if err != nil {
		gasPrice = big.NewInt(1000000000) // 1 Gwei default
	}

	// Get L1 chain ID
	l1ChainID, err := s.getL1ChainID()
	if err != nil {
		l1ChainID = big.NewInt(77700) // Default testnet
	}

	// Build transaction
	tx := types.NewTransaction(
		nonce,
		to,
		value,
		200000,   // Gas limit
		gasPrice,
		data,
	)

	// Sign transaction
	signer := types.NewEIP155Signer(l1ChainID)
	signedTx, err := types.SignTx(tx, signer, s.sequencerKey)
	if err != nil {
		return err
	}

	// Encode to RLP
	rawTx, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		return err
	}

	// Send via eth_sendRawTransaction
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendRawTransaction",
		"params":  []interface{}{"0x" + hex.EncodeToString(rawTx)},
		"id":      1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := http.Post(s.l1RPC, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if result.Error != nil {
		log.Printf("L1 error: %s", result.Error.Message)
		return nil
	}

	log.Printf("L1 tx hash: %s", result.Result)
	return nil
}

// sendL1TransactionUnsigned sends using eth_sendTransaction (for testing)
func (s *Sequencer) sendL1TransactionUnsigned(to common.Address, data []byte, value *big.Int) error {
	nonce, err := s.getL1Nonce()
	if err != nil {
		return err
	}

	tx := map[string]interface{}{
		"from":     s.coinbase.Hex(),
		"to":       to.Hex(),
		"gas":      "0x30000",
		"gasPrice": "0x3B9ACA00",
		"nonce":    "0x" + hex.EncodeToString(big.NewInt(int64(nonce)).Bytes()),
		"data":     "0x" + hex.EncodeToString(data),
		"value":    "0x0",
	}

	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendTransaction",
		"params":  []interface{}{tx},
		"id":      1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := http.Post(s.l1RPC, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if result.Error != nil {
		log.Printf("L1 error: %s", result.Error.Message)
	} else {
		log.Printf("L1 tx hash: %s", result.Result)
	}

	return nil
}

// getL1GasPrice gets current gas price from L1
func (s *Sequencer) getL1GasPrice() (*big.Int, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_gasPrice",
		"params":  []interface{}{},
		"id":      1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(s.l1RPC, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	gasPrice := new(big.Int)
	if len(result.Result) > 2 {
		gasPrice.SetString(result.Result[2:], 16)
	}

	return gasPrice, nil
}

// getL1ChainID gets chain ID from L1
func (s *Sequencer) getL1ChainID() (*big.Int, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_chainId",
		"params":  []interface{}{},
		"id":      1,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(s.l1RPC, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	chainID := new(big.Int)
	if len(result.Result) > 2 {
		chainID.SetString(result.Result[2:], 16)
	}

	return chainID, nil
}

// OnBlock sets the new block callback
func (s *Sequencer) OnBlock(callback func(*core.Block)) {
	s.onBlock = callback
}

// IsRunning returns true if sequencer is running
func (s *Sequencer) IsRunning() bool {
	return s.running
}

// GetCoinbase returns the sequencer address
func (s *Sequencer) GetCoinbase() common.Address {
	return s.coinbase
}

// SetL1Connection sets the L1 connection parameters
func (s *Sequencer) SetL1Connection(rpc string, bridge common.Address, key *ecdsa.PrivateKey) {
	s.l1RPC = rpc
	s.l1Bridge = bridge
	s.sequencerKey = key
}

// BatchSubmitter handles batch submission to L1
type BatchSubmitter struct {
	sequencer  *Sequencer
	batchSize  int
	pendingTxs []*core.Transaction
}

// NewBatchSubmitter creates a new batch submitter
func NewBatchSubmitter(seq *Sequencer, batchSize int) *BatchSubmitter {
	return &BatchSubmitter{
		sequencer: seq,
		batchSize: batchSize,
	}
}

// AddTransaction adds a transaction to the pending batch
func (b *BatchSubmitter) AddTransaction(tx *core.Transaction) {
	b.pendingTxs = append(b.pendingTxs, tx)

	if len(b.pendingTxs) >= b.batchSize {
		b.SubmitBatch()
	}
}

// SubmitBatch submits the current batch to L1
func (b *BatchSubmitter) SubmitBatch() {
	if len(b.pendingTxs) == 0 {
		return
	}

	log.Printf("Submitting batch of %d transactions to L1", len(b.pendingTxs))

	// TODO: Compress and submit batch data to L1
	// This is the data availability layer

	b.pendingTxs = nil
}
