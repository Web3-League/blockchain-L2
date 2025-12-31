package core

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ChainConfig holds L2 chain configuration
type ChainConfig struct {
	ChainID     *big.Int `json:"chainId"`
	L1ChainID   *big.Int `json:"l1ChainId"`
	L1RPC       string   `json:"l1Rpc"`
	L1Bridge    string   `json:"l1Bridge"`
	BlockTime   uint64   `json:"blockTime"`   // seconds between blocks
	SequencerPK string   `json:"sequencerPk"` // sequencer private key
}

// DefaultTurboConfig returns config for NanoPy Turbo L2
func DefaultTurboConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:   big.NewInt(77702), // NanoPy Turbo L2
		L1ChainID: big.NewInt(7770),  // NanoPy L1
		L1RPC:     "http://51.68.125.99:8545",
		BlockTime: 2, // 2 second blocks (faster than L1)
	}
}

// TestnetTurboConfig returns config for testnet L2
func TestnetTurboConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:   big.NewInt(777702), // Testnet Turbo L2
		L1ChainID: big.NewInt(77777),  // NanoPy Testnet
		L1RPC:     "http://51.68.125.99:8546",
		BlockTime: 1, // 1 second blocks on testnet
	}
}

// BlockHeader represents an L2 block header
type BlockHeader struct {
	ParentHash  common.Hash    `json:"parentHash"`
	Coinbase    common.Address `json:"miner"`
	StateRoot   common.Hash    `json:"stateRoot"`
	TxRoot      common.Hash    `json:"transactionsRoot"`
	ReceiptRoot common.Hash    `json:"receiptsRoot"`
	Number      *big.Int       `json:"number"`
	GasLimit    uint64         `json:"gasLimit"`
	GasUsed     uint64         `json:"gasUsed"`
	Timestamp   uint64         `json:"timestamp"`
	ExtraData   []byte         `json:"extraData"`
	L1BlockNum  uint64         `json:"l1BlockNumber"` // L1 block reference
}

// Hash returns the keccak256 hash of the header
func (h *BlockHeader) Hash() common.Hash {
	data := append(h.ParentHash.Bytes(), h.StateRoot.Bytes()...)
	data = append(data, h.Number.Bytes()...)
	data = append(data, big.NewInt(int64(h.Timestamp)).Bytes()...)
	return crypto.Keccak256Hash(data)
}

// Block represents a full L2 block
type Block struct {
	Header       *BlockHeader   `json:"header"`
	Transactions []*Transaction `json:"transactions"`
}

// NewBlock creates a new block
func NewBlock(header *BlockHeader, txs []*Transaction) *Block {
	return &Block{
		Header:       header,
		Transactions: txs,
	}
}

// Hash returns the block hash
func (b *Block) Hash() common.Hash {
	return b.Header.Hash()
}

// Number returns the block number
func (b *Block) Number() *big.Int {
	return b.Header.Number
}

// Transaction represents an L2 transaction
type Transaction struct {
	Nonce    uint64          `json:"nonce"`
	GasPrice *big.Int        `json:"gasPrice"`
	GasLimit uint64          `json:"gas"`
	To       *common.Address `json:"to"`
	Value    *big.Int        `json:"value"`
	Data     []byte          `json:"input"`
	V        *big.Int        `json:"v"`
	R        *big.Int        `json:"r"`
	S        *big.Int        `json:"s"`

	// Cached values
	hash common.Hash
	from common.Address
}

// Hash returns the transaction hash
func (tx *Transaction) Hash() common.Hash {
	if tx.hash == (common.Hash{}) {
		var data []byte
		if tx.To != nil {
			data = append(data, tx.To.Bytes()...)
		}
		if tx.Value != nil {
			data = append(data, tx.Value.Bytes()...)
		}
		data = append(data, tx.Data...)
		data = append(data, big.NewInt(int64(tx.Nonce)).Bytes()...)
		tx.hash = crypto.Keccak256Hash(data)
	}
	return tx.hash
}

// From returns the sender address (cached after first call)
func (tx *Transaction) From() common.Address {
	return tx.from
}

// SetFrom sets the sender address
func (tx *Transaction) SetFrom(addr common.Address) {
	tx.from = addr
}

// Receipt represents a transaction receipt
type Receipt struct {
	TxHash          common.Hash    `json:"transactionHash"`
	BlockHash       common.Hash    `json:"blockHash"`
	BlockNumber     *big.Int       `json:"blockNumber"`
	TransactionIdx  uint64         `json:"transactionIndex"`
	From            common.Address `json:"from"`
	To              common.Address `json:"to"`
	ContractAddress common.Address `json:"contractAddress,omitempty"`
	GasUsed         uint64         `json:"gasUsed"`
	CumulativeGas   uint64         `json:"cumulativeGasUsed"`
	Status          uint64         `json:"status"` // 1 = success, 0 = fail
	Logs            []*Log         `json:"logs"`
}

// Log represents an event log
type Log struct {
	Address     common.Address `json:"address"`
	Topics      []common.Hash  `json:"topics"`
	Data        []byte         `json:"data"`
	BlockNumber uint64         `json:"blockNumber"`
	TxHash      common.Hash    `json:"transactionHash"`
	TxIndex     uint64         `json:"transactionIndex"`
	BlockHash   common.Hash    `json:"blockHash"`
	LogIndex    uint64         `json:"logIndex"`
}

// Genesis represents the genesis block configuration
type Genesis struct {
	Config    *ChainConfig             `json:"config"`
	Timestamp uint64                   `json:"timestamp"`
	ExtraData []byte                   `json:"extraData"`
	GasLimit  uint64                   `json:"gasLimit"`
	Alloc     map[string]GenesisAlloc  `json:"alloc"`
}

// GenesisAlloc represents initial account state
type GenesisAlloc struct {
	Balance string `json:"balance"`
	Code    string `json:"code,omitempty"`
	Nonce   uint64 `json:"nonce,omitempty"`
}

// DefaultGenesis returns an empty default genesis for NanoPy Turbo
// Use LoadGenesis() to load from a JSON file
func DefaultGenesis() *Genesis {
	return &Genesis{
		Config:    DefaultTurboConfig(),
		Timestamp: uint64(time.Now().Unix()),
		GasLimit:  30000000, // 30M gas limit
		Alloc:     map[string]GenesisAlloc{},
	}
}

// LoadGenesis loads genesis configuration from a JSON file
func LoadGenesis(path string) (*Genesis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read genesis file: %w", err)
	}

	genesis := &Genesis{}
	if err := json.Unmarshal(data, genesis); err != nil {
		return nil, fmt.Errorf("failed to parse genesis JSON: %w", err)
	}

	// Set default config if not provided
	if genesis.Config == nil {
		genesis.Config = DefaultTurboConfig()
	}

	// Set default gas limit if not provided
	if genesis.GasLimit == 0 {
		genesis.GasLimit = 30000000
	}

	// Set timestamp if not provided
	if genesis.Timestamp == 0 {
		genesis.Timestamp = uint64(time.Now().Unix())
	}

	return genesis, nil
}

// HexToBytes converts hex string to bytes
func HexToBytes(s string) []byte {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	b, _ := hex.DecodeString(s)
	return b
}

// BytesToHex converts bytes to hex string with 0x prefix
func BytesToHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}
