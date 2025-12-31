// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title L2Bridge
 * @dev Bridge contract deployed on NanoPy Turbo L2
 *
 * Handles:
 * - Processing deposits from L1
 * - Initiating withdrawals to L1
 * - Building Merkle tree of withdrawals for L1 verification
 */
contract L2Bridge {
    // ============ State ============
    address public sequencer;
    address public l1Bridge;
    uint256 public l1ChainId;

    // Processed deposits from L1
    mapping(uint256 => bool) public processedDeposits;
    uint256 public lastProcessedDeposit;

    // Withdrawals initiated on L2
    struct Withdrawal {
        address sender;
        address recipient;
        uint256 amount;
        uint256 timestamp;
        bool included; // Included in a batch
    }
    mapping(uint256 => Withdrawal) public withdrawals;
    uint256 public withdrawalNonce;

    // Withdrawal batches for Merkle tree
    struct WithdrawalBatch {
        bytes32 merkleRoot;
        uint256 startIndex;
        uint256 endIndex;
        uint256 timestamp;
    }
    mapping(uint256 => WithdrawalBatch) public withdrawalBatches;
    uint256 public batchNonce;

    // ============ Events ============
    event DepositProcessed(uint256 indexed depositNonce, address indexed recipient, uint256 amount);
    event WithdrawalInitiated(uint256 indexed nonce, address indexed sender, address recipient, uint256 amount);
    event WithdrawalBatchCreated(uint256 indexed batchId, bytes32 merkleRoot, uint256 startIndex, uint256 endIndex);

    // ============ Modifiers ============
    modifier onlySequencer() {
        require(msg.sender == sequencer, "Only sequencer");
        _;
    }

    // ============ Constructor ============
    constructor(address _sequencer, address _l1Bridge, uint256 _l1ChainId) {
        sequencer = _sequencer;
        l1Bridge = _l1Bridge;
        l1ChainId = _l1ChainId;
    }

    // ============ Deposit Processing (L1 -> L2) ============

    /**
     * @dev Process a deposit from L1 (called by sequencer)
     * In production, this would be a system transaction included by the sequencer
     */
    function processDeposit(
        uint256 depositNonce,
        address recipient,
        uint256 amount
    ) external onlySequencer {
        require(!processedDeposits[depositNonce], "Deposit already processed");
        require(depositNonce == lastProcessedDeposit + 1, "Invalid deposit nonce");

        processedDeposits[depositNonce] = true;
        lastProcessedDeposit = depositNonce;

        // Mint the deposited amount to recipient
        // In a real L2, this would be handled by the system
        // For now, transfer from bridge balance
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        emit DepositProcessed(depositNonce, recipient, amount);
    }

    /**
     * @dev Batch process deposits (more efficient)
     */
    function processDepositBatch(
        uint256[] calldata depositNonces,
        address[] calldata recipients,
        uint256[] calldata amounts
    ) external onlySequencer {
        require(
            depositNonces.length == recipients.length && recipients.length == amounts.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < depositNonces.length; i++) {
            uint256 nonce = depositNonces[i];
            require(!processedDeposits[nonce], "Deposit already processed");
            require(nonce == lastProcessedDeposit + 1, "Invalid deposit nonce");

            processedDeposits[nonce] = true;
            lastProcessedDeposit = nonce;

            (bool success, ) = recipients[i].call{value: amounts[i]}("");
            require(success, "Transfer failed");

            emit DepositProcessed(nonce, recipients[i], amounts[i]);
        }
    }

    // ============ Withdrawals (L2 -> L1) ============

    /**
     * @dev Initiate a withdrawal to L1
     */
    function initiateWithdrawal(address recipient) external payable {
        require(msg.value > 0, "Must withdraw something");

        withdrawalNonce++;
        withdrawals[withdrawalNonce] = Withdrawal({
            sender: msg.sender,
            recipient: recipient,
            amount: msg.value,
            timestamp: block.timestamp,
            included: false
        });

        emit WithdrawalInitiated(withdrawalNonce, msg.sender, recipient, msg.value);
    }

    /**
     * @dev Initiate a withdrawal to yourself on L1
     */
    function initiateWithdrawal() external payable {
        require(msg.value > 0, "Must withdraw something");

        withdrawalNonce++;
        withdrawals[withdrawalNonce] = Withdrawal({
            sender: msg.sender,
            recipient: msg.sender,
            amount: msg.value,
            timestamp: block.timestamp,
            included: false
        });

        emit WithdrawalInitiated(withdrawalNonce, msg.sender, msg.sender, msg.value);
    }

    // ============ Withdrawal Batching ============

    /**
     * @dev Create a batch of withdrawals and compute Merkle root
     * Called by sequencer before submitting state root to L1
     */
    function createWithdrawalBatch(
        uint256 startIndex,
        uint256 endIndex
    ) external onlySequencer returns (bytes32 merkleRoot) {
        require(startIndex <= endIndex, "Invalid range");
        require(endIndex <= withdrawalNonce, "End index too high");

        // Build Merkle tree from withdrawals
        uint256 count = endIndex - startIndex + 1;
        bytes32[] memory leaves = new bytes32[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 idx = startIndex + i;
            Withdrawal storage w = withdrawals[idx];
            require(!w.included, "Withdrawal already included");

            leaves[i] = keccak256(abi.encodePacked(
                w.recipient,
                w.amount,
                block.number, // L2 block number
                idx // withdrawal index
            ));

            w.included = true;
        }

        // Compute Merkle root
        merkleRoot = computeMerkleRoot(leaves);

        batchNonce++;
        withdrawalBatches[batchNonce] = WithdrawalBatch({
            merkleRoot: merkleRoot,
            startIndex: startIndex,
            endIndex: endIndex,
            timestamp: block.timestamp
        });

        emit WithdrawalBatchCreated(batchNonce, merkleRoot, startIndex, endIndex);

        return merkleRoot;
    }

    /**
     * @dev Compute Merkle root from leaves
     */
    function computeMerkleRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        if (leaves.length == 0) return bytes32(0);
        if (leaves.length == 1) return leaves[0];

        // Pad to power of 2
        uint256 n = leaves.length;
        uint256 size = 1;
        while (size < n) size *= 2;

        bytes32[] memory tree = new bytes32[](size);
        for (uint256 i = 0; i < n; i++) {
            tree[i] = leaves[i];
        }
        for (uint256 i = n; i < size; i++) {
            tree[i] = bytes32(0);
        }

        // Build tree bottom-up
        while (size > 1) {
            for (uint256 i = 0; i < size / 2; i++) {
                bytes32 left = tree[i * 2];
                bytes32 right = tree[i * 2 + 1];
                if (left <= right) {
                    tree[i] = keccak256(abi.encodePacked(left, right));
                } else {
                    tree[i] = keccak256(abi.encodePacked(right, left));
                }
            }
            size /= 2;
        }

        return tree[0];
    }

    /**
     * @dev Get Merkle proof for a withdrawal
     */
    function getMerkleProof(
        uint256 batchId,
        uint256 withdrawalIndex
    ) external view returns (bytes32[] memory proof) {
        WithdrawalBatch storage batch = withdrawalBatches[batchId];
        require(batch.merkleRoot != bytes32(0), "Batch not found");
        require(
            withdrawalIndex >= batch.startIndex && withdrawalIndex <= batch.endIndex,
            "Withdrawal not in batch"
        );

        uint256 count = batch.endIndex - batch.startIndex + 1;
        uint256 localIndex = withdrawalIndex - batch.startIndex;

        // Rebuild leaves
        bytes32[] memory leaves = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 idx = batch.startIndex + i;
            Withdrawal storage w = withdrawals[idx];
            leaves[i] = keccak256(abi.encodePacked(
                w.recipient,
                w.amount,
                block.number,
                idx
            ));
        }

        // Pad to power of 2
        uint256 size = 1;
        while (size < count) size *= 2;

        bytes32[] memory tree = new bytes32[](size * 2);
        for (uint256 i = 0; i < count; i++) {
            tree[size + i] = leaves[i];
        }
        for (uint256 i = count; i < size; i++) {
            tree[size + i] = bytes32(0);
        }

        // Build tree
        for (uint256 i = size - 1; i > 0; i--) {
            bytes32 left = tree[i * 2];
            bytes32 right = tree[i * 2 + 1];
            if (left <= right) {
                tree[i] = keccak256(abi.encodePacked(left, right));
            } else {
                tree[i] = keccak256(abi.encodePacked(right, left));
            }
        }

        // Extract proof
        uint256 proofLength = 0;
        uint256 tempSize = size;
        while (tempSize > 1) {
            proofLength++;
            tempSize /= 2;
        }

        proof = new bytes32[](proofLength);
        uint256 idx = size + localIndex;
        for (uint256 i = 0; i < proofLength; i++) {
            if (idx % 2 == 0) {
                proof[i] = tree[idx + 1];
            } else {
                proof[i] = tree[idx - 1];
            }
            idx /= 2;
        }

        return proof;
    }

    // ============ View Functions ============

    function getWithdrawal(uint256 index) external view returns (
        address sender,
        address recipient,
        uint256 amount,
        uint256 timestamp,
        bool included
    ) {
        Withdrawal storage w = withdrawals[index];
        return (w.sender, w.recipient, w.amount, w.timestamp, w.included);
    }

    function getWithdrawalBatch(uint256 batchId) external view returns (
        bytes32 merkleRoot,
        uint256 startIndex,
        uint256 endIndex,
        uint256 timestamp
    ) {
        WithdrawalBatch storage b = withdrawalBatches[batchId];
        return (b.merkleRoot, b.startIndex, b.endIndex, b.timestamp);
    }

    function getPendingWithdrawalsCount() external view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 1; i <= withdrawalNonce; i++) {
            if (!withdrawals[i].included) count++;
        }
        return count;
    }

    // ============ Admin Functions ============

    function updateSequencer(address newSequencer) external onlySequencer {
        sequencer = newSequencer;
    }

    function updateL1Bridge(address newL1Bridge) external onlySequencer {
        l1Bridge = newL1Bridge;
    }

    // Receive ETH for processing deposits
    receive() external payable {}
}
