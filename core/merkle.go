package core

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// MerkleTree implements a binary Merkle tree for withdrawal proofs
type MerkleTree struct {
	leaves []common.Hash
	layers [][]common.Hash
	mu     sync.RWMutex
}

// NewMerkleTree creates a new empty Merkle tree
func NewMerkleTree() *MerkleTree {
	return &MerkleTree{
		leaves: make([]common.Hash, 0),
		layers: make([][]common.Hash, 0),
	}
}

// BuildFromLeaves builds the tree from a list of leaf hashes
func (m *MerkleTree) BuildFromLeaves(leaves []common.Hash) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(leaves) == 0 {
		m.leaves = nil
		m.layers = nil
		return
	}

	// Copy and sort leaves for deterministic ordering
	m.leaves = make([]common.Hash, len(leaves))
	copy(m.leaves, leaves)

	// Build layers bottom-up
	m.layers = make([][]common.Hash, 0)
	currentLayer := m.leaves

	for len(currentLayer) > 1 {
		m.layers = append(m.layers, currentLayer)
		currentLayer = m.buildNextLayer(currentLayer)
	}

	// Add root layer
	m.layers = append(m.layers, currentLayer)
}

// buildNextLayer builds the next layer from the current layer
func (m *MerkleTree) buildNextLayer(layer []common.Hash) []common.Hash {
	nextLayer := make([]common.Hash, 0, (len(layer)+1)/2)

	for i := 0; i < len(layer); i += 2 {
		if i+1 < len(layer) {
			// Hash pair of nodes (sorted for consistency with Solidity)
			nextLayer = append(nextLayer, hashPair(layer[i], layer[i+1]))
		} else {
			// Odd number of nodes - promote last one
			nextLayer = append(nextLayer, layer[i])
		}
	}

	return nextLayer
}

// hashPair hashes two nodes together (sorted order like Solidity)
func hashPair(a, b common.Hash) common.Hash {
	// Sort to match Solidity's verifyMerkleProof
	if bytes.Compare(a.Bytes(), b.Bytes()) <= 0 {
		return crypto.Keccak256Hash(append(a.Bytes(), b.Bytes()...))
	}
	return crypto.Keccak256Hash(append(b.Bytes(), a.Bytes()...))
}

// Root returns the Merkle root
func (m *MerkleTree) Root() common.Hash {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.layers) == 0 {
		return common.Hash{}
	}

	topLayer := m.layers[len(m.layers)-1]
	if len(topLayer) == 0 {
		return common.Hash{}
	}

	return topLayer[0]
}

// GetProof returns the Merkle proof for a leaf at the given index
func (m *MerkleTree) GetProof(leafIndex int) []common.Hash {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if leafIndex < 0 || leafIndex >= len(m.leaves) {
		return nil
	}

	proof := make([]common.Hash, 0)
	idx := leafIndex

	for layerIdx := 0; layerIdx < len(m.layers)-1; layerIdx++ {
		layer := m.layers[layerIdx]

		// Get sibling index
		siblingIdx := idx ^ 1 // XOR with 1 flips last bit (left<->right)

		if siblingIdx < len(layer) {
			proof = append(proof, layer[siblingIdx])
		}

		// Move to parent index
		idx = idx / 2
	}

	return proof
}

// GetProofByLeaf returns the Merkle proof for a specific leaf hash
func (m *MerkleTree) GetProofByLeaf(leaf common.Hash) []common.Hash {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Find leaf index
	for i, l := range m.leaves {
		if l == leaf {
			m.mu.RUnlock()
			return m.GetProof(i)
		}
	}

	return nil
}

// Verify verifies a Merkle proof
func VerifyMerkleProof(proof []common.Hash, root common.Hash, leaf common.Hash) bool {
	computedHash := leaf

	for _, proofElement := range proof {
		computedHash = hashPair(computedHash, proofElement)
	}

	return computedHash == root
}

// Withdrawal represents a pending withdrawal on L2
type Withdrawal struct {
	Recipient       common.Address `json:"recipient"`
	Amount          *big.Int       `json:"amount"`
	L2BlockNumber   uint64         `json:"l2BlockNumber"`
	WithdrawalIndex uint64         `json:"withdrawalIndex"`
	TxHash          common.Hash    `json:"txHash"`
	Processed       bool           `json:"processed"`
}

// Hash returns the withdrawal leaf hash (matches Solidity)
func (w *Withdrawal) Hash() common.Hash {
	// Match Solidity: keccak256(abi.encodePacked(recipient, amount, l2BlockNumber, withdrawalIndex))
	data := make([]byte, 0, 20+32+8+8)
	data = append(data, w.Recipient.Bytes()...)

	// Amount as 32 bytes (big-endian, padded)
	amountBytes := make([]byte, 32)
	if w.Amount != nil {
		amountBig := w.Amount.Bytes()
		copy(amountBytes[32-len(amountBig):], amountBig)
	}
	data = append(data, amountBytes...)

	// Block number as 32 bytes (uint256 in Solidity)
	blockBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(blockBytes[24:], w.L2BlockNumber)
	data = append(data, blockBytes...)

	// Withdrawal index as 32 bytes (uint256 in Solidity)
	indexBytes := make([]byte, 32)
	binary.BigEndian.PutUint64(indexBytes[24:], w.WithdrawalIndex)
	data = append(data, indexBytes...)

	return crypto.Keccak256Hash(data)
}

// WithdrawalManager tracks withdrawals and builds Merkle trees
type WithdrawalManager struct {
	withdrawals     map[uint64]*Withdrawal // indexed by withdrawalIndex
	pendingByBlock  map[uint64][]uint64    // block -> withdrawal indices
	nextIndex       uint64
	mu              sync.RWMutex
}

// NewWithdrawalManager creates a new withdrawal manager
func NewWithdrawalManager() *WithdrawalManager {
	return &WithdrawalManager{
		withdrawals:    make(map[uint64]*Withdrawal),
		pendingByBlock: make(map[uint64][]uint64),
		nextIndex:      0,
	}
}

// AddWithdrawal adds a new withdrawal
func (wm *WithdrawalManager) AddWithdrawal(recipient common.Address, amount *big.Int, blockNumber uint64, txHash common.Hash) *Withdrawal {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	w := &Withdrawal{
		Recipient:       recipient,
		Amount:          new(big.Int).Set(amount),
		L2BlockNumber:   blockNumber,
		WithdrawalIndex: wm.nextIndex,
		TxHash:          txHash,
		Processed:       false,
	}

	wm.withdrawals[wm.nextIndex] = w
	wm.pendingByBlock[blockNumber] = append(wm.pendingByBlock[blockNumber], wm.nextIndex)
	wm.nextIndex++

	return w
}

// GetWithdrawal returns a withdrawal by index
func (wm *WithdrawalManager) GetWithdrawal(index uint64) *Withdrawal {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	return wm.withdrawals[index]
}

// GetWithdrawalsForBlock returns all withdrawals in a block
func (wm *WithdrawalManager) GetWithdrawalsForBlock(blockNumber uint64) []*Withdrawal {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	indices := wm.pendingByBlock[blockNumber]
	result := make([]*Withdrawal, 0, len(indices))

	for _, idx := range indices {
		if w := wm.withdrawals[idx]; w != nil {
			result = append(result, w)
		}
	}

	return result
}

// GetPendingWithdrawals returns all pending (unprocessed) withdrawals
func (wm *WithdrawalManager) GetPendingWithdrawals() []*Withdrawal {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	result := make([]*Withdrawal, 0)
	for _, w := range wm.withdrawals {
		if !w.Processed {
			result = append(result, w)
		}
	}

	// Sort by index for deterministic order
	sort.Slice(result, func(i, j int) bool {
		return result[i].WithdrawalIndex < result[j].WithdrawalIndex
	})

	return result
}

// BuildMerkleTree builds a Merkle tree from pending withdrawals
func (wm *WithdrawalManager) BuildMerkleTree() (*MerkleTree, common.Hash) {
	pending := wm.GetPendingWithdrawals()

	if len(pending) == 0 {
		return NewMerkleTree(), common.Hash{}
	}

	// Build leaf hashes
	leaves := make([]common.Hash, len(pending))
	for i, w := range pending {
		leaves[i] = w.Hash()
	}

	tree := NewMerkleTree()
	tree.BuildFromLeaves(leaves)

	return tree, tree.Root()
}

// GetMerkleProof returns the Merkle proof for a withdrawal
func (wm *WithdrawalManager) GetMerkleProof(withdrawalIndex uint64) ([]common.Hash, common.Hash, error) {
	wm.mu.RLock()
	w := wm.withdrawals[withdrawalIndex]
	wm.mu.RUnlock()

	if w == nil {
		return nil, common.Hash{}, nil
	}

	// Rebuild tree and get proof
	tree, root := wm.BuildMerkleTree()

	// Find the index of this withdrawal in the pending list
	pending := wm.GetPendingWithdrawals()
	leafIdx := -1
	for i, pw := range pending {
		if pw.WithdrawalIndex == withdrawalIndex {
			leafIdx = i
			break
		}
	}

	if leafIdx == -1 {
		return nil, common.Hash{}, nil
	}

	proof := tree.GetProof(leafIdx)
	return proof, root, nil
}

// MarkProcessed marks a withdrawal as processed
func (wm *WithdrawalManager) MarkProcessed(index uint64) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	if w := wm.withdrawals[index]; w != nil {
		w.Processed = true
	}
}

// Count returns the total number of withdrawals
func (wm *WithdrawalManager) Count() uint64 {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	return wm.nextIndex
}

// PendingCount returns the number of pending withdrawals
func (wm *WithdrawalManager) PendingCount() int {
	return len(wm.GetPendingWithdrawals())
}
