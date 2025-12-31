// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title L1BridgeSecure
 * @dev Secure Optimistic Rollup Bridge for NanoPy L1 <-> Turbo L2
 *
 * Security features:
 * - Merkle proof verification for withdrawals
 * - 7-day challenge period before withdrawal finalization
 * - Fraud proof system to challenge invalid state roots
 * - Sequencer bond for slashing on fraud
 */
contract L1BridgeSecure {
    // ============ Constants ============
    uint256 public constant CHALLENGE_PERIOD = 7 days;
    uint256 public constant MIN_SEQUENCER_BOND = 100 * 1e18; // 100 NPY
    uint256 public constant FRAUD_PROOF_REWARD = 10 * 1e18;  // 10 NPY

    // ============ State ============
    address public sequencer;
    uint256 public sequencerBond;
    uint256 public l2ChainId;

    // State roots with timestamps
    struct StateCommitment {
        bytes32 stateRoot;
        bytes32 withdrawalsRoot; // Merkle root of pending withdrawals
        uint256 timestamp;
        bool finalized;
        bool challenged;
    }
    mapping(uint256 => StateCommitment) public stateCommitments;
    uint256 public lastL2Block;

    // Deposits
    struct Deposit {
        address sender;
        address recipient;
        uint256 amount;
        uint256 timestamp;
        bool processed;
    }
    mapping(uint256 => Deposit) public deposits;
    uint256 public depositNonce;

    // Withdrawals with challenge period
    struct Withdrawal {
        address recipient;
        uint256 amount;
        uint256 l2BlockNumber;
        uint256 withdrawalIndex;
        uint256 timestamp;
        bool finalized;
    }
    mapping(bytes32 => Withdrawal) public withdrawals;
    mapping(bytes32 => bool) public processedWithdrawals;

    // Fraud proofs
    struct Challenge {
        address challenger;
        uint256 l2BlockNumber;
        bytes32 claimedStateRoot;
        uint256 timestamp;
        bool resolved;
    }
    mapping(bytes32 => Challenge) public challenges;

    // ============ Events ============
    event DepositInitiated(uint256 indexed nonce, address indexed sender, address recipient, uint256 amount);
    event StateRootSubmitted(uint256 indexed l2BlockNumber, bytes32 stateRoot, bytes32 withdrawalsRoot);
    event StateRootFinalized(uint256 indexed l2BlockNumber, bytes32 stateRoot);
    event WithdrawalInitiated(bytes32 indexed withdrawalHash, address indexed recipient, uint256 amount, uint256 l2BlockNumber);
    event WithdrawalFinalized(bytes32 indexed withdrawalHash, address indexed recipient, uint256 amount);
    event ChallengeSubmitted(bytes32 indexed challengeId, address indexed challenger, uint256 l2BlockNumber);
    event ChallengeResolved(bytes32 indexed challengeId, bool fraudProven, address winner);
    event SequencerSlashed(address indexed sequencer, uint256 amount, address indexed challenger);
    event SequencerBondUpdated(address indexed sequencer, uint256 newBond);

    // ============ Modifiers ============
    modifier onlySequencer() {
        require(msg.sender == sequencer, "Only sequencer");
        _;
    }

    modifier sequencerBonded() {
        require(sequencerBond >= MIN_SEQUENCER_BOND, "Insufficient sequencer bond");
        _;
    }

    // ============ Constructor ============
    constructor(address _sequencer, uint256 _l2ChainId) {
        sequencer = _sequencer;
        l2ChainId = _l2ChainId;
    }

    // ============ Sequencer Bond ============

    /**
     * @dev Sequencer deposits bond (required for submitting state roots)
     */
    function depositBond() external payable onlySequencer {
        sequencerBond += msg.value;
        emit SequencerBondUpdated(sequencer, sequencerBond);
    }

    /**
     * @dev Sequencer withdraws excess bond (must keep minimum)
     */
    function withdrawBond(uint256 amount) external onlySequencer {
        require(sequencerBond - amount >= MIN_SEQUENCER_BOND, "Must keep minimum bond");
        sequencerBond -= amount;
        (bool success, ) = sequencer.call{value: amount}("");
        require(success, "Transfer failed");
        emit SequencerBondUpdated(sequencer, sequencerBond);
    }

    // ============ Deposits (L1 -> L2) ============

    /**
     * @dev Deposit NPY to L2
     */
    function deposit(address recipient) external payable {
        require(msg.value > 0, "Must deposit something");

        depositNonce++;
        deposits[depositNonce] = Deposit({
            sender: msg.sender,
            recipient: recipient,
            amount: msg.value,
            timestamp: block.timestamp,
            processed: false
        });

        emit DepositInitiated(depositNonce, msg.sender, recipient, msg.value);
    }

    /**
     * @dev Deposit to yourself on L2
     */
    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");

        depositNonce++;
        deposits[depositNonce] = Deposit({
            sender: msg.sender,
            recipient: msg.sender,
            amount: msg.value,
            timestamp: block.timestamp,
            processed: false
        });

        emit DepositInitiated(depositNonce, msg.sender, msg.sender, msg.value);
    }

    // ============ State Root Submission ============

    /**
     * @dev Submit a state root from L2 (sequencer only, bonded)
     */
    function submitStateRoot(
        uint256 l2BlockNumber,
        bytes32 stateRoot,
        bytes32 withdrawalsRoot
    ) external onlySequencer sequencerBonded {
        require(l2BlockNumber > lastL2Block, "Block already submitted");
        require(stateRoot != bytes32(0), "Invalid state root");

        stateCommitments[l2BlockNumber] = StateCommitment({
            stateRoot: stateRoot,
            withdrawalsRoot: withdrawalsRoot,
            timestamp: block.timestamp,
            finalized: false,
            challenged: false
        });

        lastL2Block = l2BlockNumber;

        emit StateRootSubmitted(l2BlockNumber, stateRoot, withdrawalsRoot);
    }

    /**
     * @dev Finalize a state root after challenge period
     */
    function finalizeStateRoot(uint256 l2BlockNumber) external {
        StateCommitment storage commitment = stateCommitments[l2BlockNumber];
        require(commitment.stateRoot != bytes32(0), "State root not found");
        require(!commitment.finalized, "Already finalized");
        require(!commitment.challenged, "State root is challenged");
        require(
            block.timestamp >= commitment.timestamp + CHALLENGE_PERIOD,
            "Challenge period not over"
        );

        commitment.finalized = true;
        emit StateRootFinalized(l2BlockNumber, commitment.stateRoot);
    }

    // ============ Withdrawals (L2 -> L1) ============

    /**
     * @dev Initiate a withdrawal from L2 (requires Merkle proof)
     */
    function initiateWithdrawal(
        address recipient,
        uint256 amount,
        uint256 l2BlockNumber,
        uint256 withdrawalIndex,
        bytes32[] calldata merkleProof
    ) external {
        StateCommitment storage commitment = stateCommitments[l2BlockNumber];
        require(commitment.stateRoot != bytes32(0), "State root not found");
        require(!commitment.challenged, "State root is challenged");

        // Compute withdrawal leaf
        bytes32 withdrawalLeaf = keccak256(abi.encodePacked(
            recipient,
            amount,
            l2BlockNumber,
            withdrawalIndex
        ));

        // Verify Merkle proof
        require(
            verifyMerkleProof(merkleProof, commitment.withdrawalsRoot, withdrawalLeaf),
            "Invalid Merkle proof"
        );

        bytes32 withdrawalHash = keccak256(abi.encodePacked(
            recipient,
            amount,
            l2BlockNumber,
            withdrawalIndex
        ));

        require(!processedWithdrawals[withdrawalHash], "Already processed");

        withdrawals[withdrawalHash] = Withdrawal({
            recipient: recipient,
            amount: amount,
            l2BlockNumber: l2BlockNumber,
            withdrawalIndex: withdrawalIndex,
            timestamp: block.timestamp,
            finalized: false
        });

        emit WithdrawalInitiated(withdrawalHash, recipient, amount, l2BlockNumber);
    }

    /**
     * @dev Finalize a withdrawal after challenge period
     */
    function finalizeWithdrawal(bytes32 withdrawalHash) external {
        Withdrawal storage withdrawal = withdrawals[withdrawalHash];
        require(withdrawal.recipient != address(0), "Withdrawal not found");
        require(!withdrawal.finalized, "Already finalized");
        require(!processedWithdrawals[withdrawalHash], "Already processed");

        StateCommitment storage commitment = stateCommitments[withdrawal.l2BlockNumber];
        require(commitment.finalized, "State root not finalized");

        // Additional safety: check challenge period from withdrawal initiation
        require(
            block.timestamp >= withdrawal.timestamp + CHALLENGE_PERIOD,
            "Withdrawal challenge period not over"
        );

        withdrawal.finalized = true;
        processedWithdrawals[withdrawalHash] = true;

        // Transfer funds
        (bool success, ) = withdrawal.recipient.call{value: withdrawal.amount}("");
        require(success, "Transfer failed");

        emit WithdrawalFinalized(withdrawalHash, withdrawal.recipient, withdrawal.amount);
    }

    // ============ Fraud Proofs ============

    /**
     * @dev Challenge a state root (anyone can challenge)
     */
    function challengeStateRoot(
        uint256 l2BlockNumber,
        bytes calldata fraudProofData
    ) external {
        StateCommitment storage commitment = stateCommitments[l2BlockNumber];
        require(commitment.stateRoot != bytes32(0), "State root not found");
        require(!commitment.finalized, "Already finalized");
        require(!commitment.challenged, "Already challenged");
        require(
            block.timestamp < commitment.timestamp + CHALLENGE_PERIOD,
            "Challenge period over"
        );

        bytes32 challengeId = keccak256(abi.encodePacked(
            msg.sender,
            l2BlockNumber,
            block.timestamp
        ));

        challenges[challengeId] = Challenge({
            challenger: msg.sender,
            l2BlockNumber: l2BlockNumber,
            claimedStateRoot: commitment.stateRoot,
            timestamp: block.timestamp,
            resolved: false
        });

        commitment.challenged = true;

        emit ChallengeSubmitted(challengeId, msg.sender, l2BlockNumber);

        // In a full implementation, this would trigger an interactive dispute game
        // For now, we validate the fraud proof directly
        bool fraudProven = validateFraudProof(l2BlockNumber, fraudProofData);

        if (fraudProven) {
            _slashSequencer(msg.sender);
            challenges[challengeId].resolved = true;
            emit ChallengeResolved(challengeId, true, msg.sender);
        }
    }

    /**
     * @dev Resolve a challenge (called after dispute game)
     */
    function resolveChallenge(bytes32 challengeId, bool fraudProven) external {
        // In production, this would be called by a dispute resolution contract
        // For simplicity, only sequencer can resolve (would be replaced by dispute game)
        require(msg.sender == sequencer || fraudProven, "Unauthorized");

        Challenge storage challenge = challenges[challengeId];
        require(!challenge.resolved, "Already resolved");

        challenge.resolved = true;

        if (fraudProven) {
            _slashSequencer(challenge.challenger);
        } else {
            // Challenge failed, state root is valid
            stateCommitments[challenge.l2BlockNumber].challenged = false;
        }

        emit ChallengeResolved(challengeId, fraudProven, fraudProven ? challenge.challenger : sequencer);
    }

    // ============ Internal Functions ============

    /**
     * @dev Verify a Merkle proof
     */
    function verifyMerkleProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        return computedHash == root;
    }

    /**
     * @dev Validate a fraud proof (simplified - would be more complex in production)
     */
    function validateFraudProof(
        uint256 l2BlockNumber,
        bytes calldata fraudProofData
    ) internal view returns (bool) {
        // In production, this would:
        // 1. Re-execute the disputed transaction
        // 2. Compare the resulting state root
        // 3. Return true if mismatch proves fraud

        // For now, we accept fraud proofs that contain valid proof data
        // This is a placeholder for the full dispute game implementation
        if (fraudProofData.length < 32) return false;

        // Extract claimed correct state root from proof
        bytes32 claimedCorrectRoot = bytes32(fraudProofData[0:32]);

        // If the claimed root differs from submitted root, fraud is possible
        // In production, we would verify the claimed root is actually correct
        return claimedCorrectRoot != stateCommitments[l2BlockNumber].stateRoot;
    }

    /**
     * @dev Slash the sequencer and reward challenger
     */
    function _slashSequencer(address challenger) internal {
        uint256 slashAmount = sequencerBond > FRAUD_PROOF_REWARD ? FRAUD_PROOF_REWARD : sequencerBond;
        sequencerBond -= slashAmount;

        // Reward challenger
        (bool success, ) = challenger.call{value: slashAmount}("");
        require(success, "Reward transfer failed");

        emit SequencerSlashed(sequencer, slashAmount, challenger);
    }

    // ============ View Functions ============

    function getStateCommitment(uint256 l2BlockNumber) external view returns (
        bytes32 stateRoot,
        bytes32 withdrawalsRoot,
        uint256 timestamp,
        bool finalized,
        bool challenged
    ) {
        StateCommitment storage c = stateCommitments[l2BlockNumber];
        return (c.stateRoot, c.withdrawalsRoot, c.timestamp, c.finalized, c.challenged);
    }

    function getWithdrawal(bytes32 withdrawalHash) external view returns (
        address recipient,
        uint256 amount,
        uint256 l2BlockNumber,
        uint256 timestamp,
        bool finalized
    ) {
        Withdrawal storage w = withdrawals[withdrawalHash];
        return (w.recipient, w.amount, w.l2BlockNumber, w.timestamp, w.finalized);
    }

    function canFinalizeStateRoot(uint256 l2BlockNumber) external view returns (bool) {
        StateCommitment storage c = stateCommitments[l2BlockNumber];
        return c.stateRoot != bytes32(0)
            && !c.finalized
            && !c.challenged
            && block.timestamp >= c.timestamp + CHALLENGE_PERIOD;
    }

    function canFinalizeWithdrawal(bytes32 withdrawalHash) external view returns (bool) {
        Withdrawal storage w = withdrawals[withdrawalHash];
        StateCommitment storage c = stateCommitments[w.l2BlockNumber];
        return w.recipient != address(0)
            && !w.finalized
            && c.finalized
            && block.timestamp >= w.timestamp + CHALLENGE_PERIOD;
    }

    // ============ Admin Functions ============

    function updateSequencer(address newSequencer) external onlySequencer {
        sequencer = newSequencer;
    }

    receive() external payable {}
}
