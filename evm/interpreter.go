package evm

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	ErrOutOfGas              = errors.New("out of gas")
	ErrStackOverflow         = errors.New("stack overflow")
	ErrStackUnderflow        = errors.New("stack underflow")
	ErrInvalidJump           = errors.New("invalid jump destination")
	ErrWriteProtection       = errors.New("write protection")
	ErrReturnDataOutOfBounds = errors.New("return data out of bounds")
	ErrInvalidOpcode         = errors.New("invalid opcode")
	ErrDepthExceeded         = errors.New("max call depth exceeded")
)

// StateDB interface for EVM state access
type StateDB interface {
	GetBalance(addr common.Address) *big.Int
	SetBalance(addr common.Address, amount *big.Int)
	AddBalance(addr common.Address, amount *big.Int)
	SubBalance(addr common.Address, amount *big.Int)

	GetNonce(addr common.Address) uint64
	SetNonce(addr common.Address, nonce uint64)

	GetCode(addr common.Address) []byte
	SetCode(addr common.Address, code []byte)
	GetCodeHash(addr common.Address) common.Hash
	GetCodeSize(addr common.Address) int

	GetStorage(addr common.Address, key common.Hash) common.Hash
	SetStorage(addr common.Address, key, value common.Hash)

	Exist(addr common.Address) bool
	Empty(addr common.Address) bool

	CreateAccount(addr common.Address)
	SelfDestruct(addr common.Address)

	Snapshot() int
	RevertToSnapshot(int)
}

// Context provides block and transaction context
type Context struct {
	Origin      common.Address // Transaction sender
	GasPrice    *big.Int       // Gas price
	Coinbase    common.Address // Block coinbase
	GasLimit    uint64         // Block gas limit
	BlockNumber *big.Int       // Block number
	Time        uint64         // Block timestamp
	Difficulty  *big.Int       // Block difficulty (for PREVRANDAO)
	BaseFee     *big.Int       // Base fee
	ChainID     *big.Int       // Chain ID
}

// Contract represents a contract being executed
type Contract struct {
	Caller   common.Address // Caller address
	Address  common.Address // Contract address
	Value    *big.Int       // Value sent
	Input    []byte         // Call input data
	Code     []byte         // Contract bytecode
	CodeHash common.Hash    // Code hash
	Gas      uint64         // Gas available
}

// ExecutionResult contains execution output
type ExecutionResult struct {
	ReturnData []byte
	GasUsed    uint64
	Err        error
}

// Log represents an EVM log entry
type Log struct {
	Address common.Address
	Topics  []common.Hash
	Data    []byte
}

// Interpreter executes EVM bytecode
type Interpreter struct {
	state      StateDB
	ctx        *Context
	contract   *Contract
	memory     *Memory
	stack      *Stack
	returnData []byte
	pc         uint64
	gas        uint64
	readOnly   bool
	depth      int
	logs       []*Log
	jumpDests  map[uint64]bool
}

// NewInterpreter creates a new EVM interpreter
func NewInterpreter(state StateDB, ctx *Context) *Interpreter {
	return &Interpreter{
		state:     state,
		ctx:       ctx,
		memory:    NewMemory(),
		stack:     NewStack(),
		logs:      make([]*Log, 0),
		jumpDests: make(map[uint64]bool),
	}
}

// Execute runs the contract code
func (i *Interpreter) Execute(contract *Contract, input []byte, readOnly bool) *ExecutionResult {
	i.contract = contract
	i.contract.Input = input
	i.gas = contract.Gas
	i.readOnly = readOnly
	i.pc = 0
	i.returnData = nil

	// Analyze jump destinations
	i.analyzeJumpDests(contract.Code)

	// Main execution loop
	for {
		if i.pc >= uint64(len(contract.Code)) {
			break
		}

		op := OpCode(contract.Code[i.pc])

		// Check gas
		gasCost := i.getGasCost(op)
		if i.gas < gasCost {
			return &ExecutionResult{Err: ErrOutOfGas, GasUsed: contract.Gas}
		}
		i.gas -= gasCost

		// Execute opcode
		result, err := i.executeOp(op)
		if err != nil {
			return &ExecutionResult{Err: err, GasUsed: contract.Gas - i.gas}
		}

		if result != nil {
			return &ExecutionResult{
				ReturnData: result,
				GasUsed:    contract.Gas - i.gas,
			}
		}

		i.pc++
	}

	return &ExecutionResult{GasUsed: contract.Gas - i.gas}
}

// analyzeJumpDests finds all valid JUMPDEST positions
func (i *Interpreter) analyzeJumpDests(code []byte) {
	i.jumpDests = make(map[uint64]bool)
	for pc := uint64(0); pc < uint64(len(code)); pc++ {
		op := OpCode(code[pc])
		if op == JUMPDEST {
			i.jumpDests[pc] = true
		}
		// Skip PUSH data
		if op >= PUSH1 && op <= PUSH32 {
			pc += uint64(op - PUSH1 + 1)
		}
	}
}

// getGasCost returns the gas cost for an opcode
func (i *Interpreter) getGasCost(op OpCode) uint64 {
	info, ok := OpCodeInfos[op]
	if !ok {
		return 0
	}
	return info.Gas
}

// executeOp executes a single opcode
func (i *Interpreter) executeOp(op OpCode) ([]byte, error) {
	switch op {
	case STOP:
		return []byte{}, nil

	case ADD:
		x, y := i.stack.Pop(), i.stack.Pop()
		i.stack.Push(new(big.Int).Add(x, y))

	case MUL:
		x, y := i.stack.Pop(), i.stack.Pop()
		i.stack.Push(new(big.Int).Mul(x, y))

	case SUB:
		x, y := i.stack.Pop(), i.stack.Pop()
		i.stack.Push(new(big.Int).Sub(x, y))

	case DIV:
		x, y := i.stack.Pop(), i.stack.Pop()
		if y.Sign() == 0 {
			i.stack.Push(big.NewInt(0))
		} else {
			i.stack.Push(new(big.Int).Div(x, y))
		}

	case SDIV:
		x, y := i.stack.Pop(), i.stack.Pop()
		if y.Sign() == 0 {
			i.stack.Push(big.NewInt(0))
		} else {
			i.stack.Push(signedDiv(x, y))
		}

	case MOD:
		x, y := i.stack.Pop(), i.stack.Pop()
		if y.Sign() == 0 {
			i.stack.Push(big.NewInt(0))
		} else {
			i.stack.Push(new(big.Int).Mod(x, y))
		}

	case SMOD:
		x, y := i.stack.Pop(), i.stack.Pop()
		if y.Sign() == 0 {
			i.stack.Push(big.NewInt(0))
		} else {
			i.stack.Push(signedMod(x, y))
		}

	case ADDMOD:
		x, y, z := i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		if z.Sign() == 0 {
			i.stack.Push(big.NewInt(0))
		} else {
			result := new(big.Int).Add(x, y)
			i.stack.Push(result.Mod(result, z))
		}

	case MULMOD:
		x, y, z := i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		if z.Sign() == 0 {
			i.stack.Push(big.NewInt(0))
		} else {
			result := new(big.Int).Mul(x, y)
			i.stack.Push(result.Mod(result, z))
		}

	case EXP:
		base, exp := i.stack.Pop(), i.stack.Pop()
		// Additional gas for EXP
		if exp.Sign() > 0 {
			expBytes := uint64((exp.BitLen() + 7) / 8)
			extraGas := expBytes * 50
			if i.gas < extraGas {
				return nil, ErrOutOfGas
			}
			i.gas -= extraGas
		}
		i.stack.Push(new(big.Int).Exp(base, exp, tt256))

	case SIGNEXTEND:
		back, num := i.stack.Pop(), i.stack.Pop()
		i.stack.Push(signExtend(back, num))

	case LT:
		x, y := i.stack.Pop(), i.stack.Pop()
		if x.Cmp(y) < 0 {
			i.stack.Push(big.NewInt(1))
		} else {
			i.stack.Push(big.NewInt(0))
		}

	case GT:
		x, y := i.stack.Pop(), i.stack.Pop()
		if x.Cmp(y) > 0 {
			i.stack.Push(big.NewInt(1))
		} else {
			i.stack.Push(big.NewInt(0))
		}

	case SLT:
		x, y := i.stack.Pop(), i.stack.Pop()
		if signedCmp(x, y) < 0 {
			i.stack.Push(big.NewInt(1))
		} else {
			i.stack.Push(big.NewInt(0))
		}

	case SGT:
		x, y := i.stack.Pop(), i.stack.Pop()
		if signedCmp(x, y) > 0 {
			i.stack.Push(big.NewInt(1))
		} else {
			i.stack.Push(big.NewInt(0))
		}

	case EQ:
		x, y := i.stack.Pop(), i.stack.Pop()
		if x.Cmp(y) == 0 {
			i.stack.Push(big.NewInt(1))
		} else {
			i.stack.Push(big.NewInt(0))
		}

	case ISZERO:
		x := i.stack.Pop()
		if x.Sign() == 0 {
			i.stack.Push(big.NewInt(1))
		} else {
			i.stack.Push(big.NewInt(0))
		}

	case AND:
		x, y := i.stack.Pop(), i.stack.Pop()
		i.stack.Push(new(big.Int).And(x, y))

	case OR:
		x, y := i.stack.Pop(), i.stack.Pop()
		i.stack.Push(new(big.Int).Or(x, y))

	case XOR:
		x, y := i.stack.Pop(), i.stack.Pop()
		i.stack.Push(new(big.Int).Xor(x, y))

	case NOT:
		x := i.stack.Pop()
		i.stack.Push(new(big.Int).Not(x))

	case BYTE:
		th, val := i.stack.Pop(), i.stack.Pop()
		if th.Cmp(big.NewInt(32)) < 0 {
			b := byte(0)
			if val.BitLen() > 0 {
				bytes := val.Bytes()
				idx := int(th.Uint64())
				if idx < len(bytes) {
					// Big-endian
					actualIdx := len(bytes) - 32 + idx
					if actualIdx >= 0 && actualIdx < len(bytes) {
						b = bytes[actualIdx]
					}
				}
			}
			i.stack.Push(big.NewInt(int64(b)))
		} else {
			i.stack.Push(big.NewInt(0))
		}

	case SHL:
		shift, value := i.stack.Pop(), i.stack.Pop()
		if shift.Cmp(big.NewInt(256)) >= 0 {
			i.stack.Push(big.NewInt(0))
		} else {
			result := new(big.Int).Lsh(value, uint(shift.Uint64()))
			i.stack.Push(result.And(result, tt256m1))
		}

	case SHR:
		shift, value := i.stack.Pop(), i.stack.Pop()
		if shift.Cmp(big.NewInt(256)) >= 0 {
			i.stack.Push(big.NewInt(0))
		} else {
			i.stack.Push(new(big.Int).Rsh(value, uint(shift.Uint64())))
		}

	case SAR:
		shift, value := i.stack.Pop(), i.stack.Pop()
		i.stack.Push(signedRightShift(value, shift))

	case KECCAK256:
		offset, size := i.stack.Pop(), i.stack.Pop()
		// Memory expansion cost
		if err := i.useGasForMemory(offset.Uint64(), size.Uint64()); err != nil {
			return nil, err
		}
		data := i.memory.GetCopy(offset.Uint64(), size.Uint64())
		hash := crypto.Keccak256(data)
		i.stack.Push(new(big.Int).SetBytes(hash))

	case ADDRESS:
		i.stack.Push(new(big.Int).SetBytes(i.contract.Address.Bytes()))

	case BALANCE:
		addr := common.BigToAddress(i.stack.Pop())
		balance := i.state.GetBalance(addr)
		i.stack.Push(new(big.Int).Set(balance))

	case ORIGIN:
		i.stack.Push(new(big.Int).SetBytes(i.ctx.Origin.Bytes()))

	case CALLER:
		i.stack.Push(new(big.Int).SetBytes(i.contract.Caller.Bytes()))

	case CALLVALUE:
		i.stack.Push(new(big.Int).Set(i.contract.Value))

	case CALLDATALOAD:
		offset := i.stack.Pop()
		data := getDataBig(i.contract.Input, offset, big.NewInt(32))
		i.stack.Push(new(big.Int).SetBytes(data))

	case CALLDATASIZE:
		i.stack.Push(big.NewInt(int64(len(i.contract.Input))))

	case CALLDATACOPY:
		memOffset, dataOffset, length := i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		if err := i.useGasForMemory(memOffset.Uint64(), length.Uint64()); err != nil {
			return nil, err
		}
		data := getDataBig(i.contract.Input, dataOffset, length)
		i.memory.Set(memOffset.Uint64(), length.Uint64(), data)

	case CODESIZE:
		i.stack.Push(big.NewInt(int64(len(i.contract.Code))))

	case CODECOPY:
		memOffset, codeOffset, length := i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		if err := i.useGasForMemory(memOffset.Uint64(), length.Uint64()); err != nil {
			return nil, err
		}
		data := getDataBig(i.contract.Code, codeOffset, length)
		i.memory.Set(memOffset.Uint64(), length.Uint64(), data)

	case GASPRICE:
		i.stack.Push(new(big.Int).Set(i.ctx.GasPrice))

	case EXTCODESIZE:
		addr := common.BigToAddress(i.stack.Pop())
		i.stack.Push(big.NewInt(int64(i.state.GetCodeSize(addr))))

	case EXTCODECOPY:
		addr := common.BigToAddress(i.stack.Pop())
		memOffset, codeOffset, length := i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		if err := i.useGasForMemory(memOffset.Uint64(), length.Uint64()); err != nil {
			return nil, err
		}
		code := i.state.GetCode(addr)
		data := getDataBig(code, codeOffset, length)
		i.memory.Set(memOffset.Uint64(), length.Uint64(), data)

	case RETURNDATASIZE:
		i.stack.Push(big.NewInt(int64(len(i.returnData))))

	case RETURNDATACOPY:
		memOffset, dataOffset, length := i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		end := new(big.Int).Add(dataOffset, length)
		if end.Cmp(big.NewInt(int64(len(i.returnData)))) > 0 {
			return nil, ErrReturnDataOutOfBounds
		}
		if err := i.useGasForMemory(memOffset.Uint64(), length.Uint64()); err != nil {
			return nil, err
		}
		i.memory.Set(memOffset.Uint64(), length.Uint64(), i.returnData[dataOffset.Uint64():end.Uint64()])

	case EXTCODEHASH:
		addr := common.BigToAddress(i.stack.Pop())
		if !i.state.Exist(addr) {
			i.stack.Push(big.NewInt(0))
		} else {
			hash := i.state.GetCodeHash(addr)
			i.stack.Push(new(big.Int).SetBytes(hash.Bytes()))
		}

	case BLOCKHASH:
		num := i.stack.Pop()
		// Simplified - return zero for now
		_ = num
		i.stack.Push(big.NewInt(0))

	case COINBASE:
		i.stack.Push(new(big.Int).SetBytes(i.ctx.Coinbase.Bytes()))

	case TIMESTAMP:
		i.stack.Push(big.NewInt(int64(i.ctx.Time)))

	case NUMBER:
		i.stack.Push(new(big.Int).Set(i.ctx.BlockNumber))

	case PREVRANDAO:
		i.stack.Push(new(big.Int).Set(i.ctx.Difficulty))

	case GASLIMIT:
		i.stack.Push(big.NewInt(int64(i.ctx.GasLimit)))

	case CHAINID:
		i.stack.Push(new(big.Int).Set(i.ctx.ChainID))

	case SELFBALANCE:
		balance := i.state.GetBalance(i.contract.Address)
		i.stack.Push(new(big.Int).Set(balance))

	case BASEFEE:
		i.stack.Push(new(big.Int).Set(i.ctx.BaseFee))

	case POP:
		i.stack.Pop()

	case MLOAD:
		offset := i.stack.Pop()
		if err := i.useGasForMemory(offset.Uint64(), 32); err != nil {
			return nil, err
		}
		data := i.memory.GetCopy(offset.Uint64(), 32)
		i.stack.Push(new(big.Int).SetBytes(data))

	case MSTORE:
		offset, val := i.stack.Pop(), i.stack.Pop()
		if err := i.useGasForMemory(offset.Uint64(), 32); err != nil {
			return nil, err
		}
		i.memory.Set32(offset.Uint64(), val)

	case MSTORE8:
		offset, val := i.stack.Pop(), i.stack.Pop()
		if err := i.useGasForMemory(offset.Uint64(), 1); err != nil {
			return nil, err
		}
		i.memory.SetByte(offset.Uint64(), byte(val.Uint64()&0xFF))

	case SLOAD:
		key := i.stack.Pop()
		val := i.state.GetStorage(i.contract.Address, common.BigToHash(key))
		i.stack.Push(new(big.Int).SetBytes(val.Bytes()))

	case SSTORE:
		if i.readOnly {
			return nil, ErrWriteProtection
		}
		key, val := i.stack.Pop(), i.stack.Pop()
		// Gas calculation for SSTORE is complex, simplified here
		i.state.SetStorage(i.contract.Address, common.BigToHash(key), common.BigToHash(val))

	case JUMP:
		dest := i.stack.Pop()
		if !i.jumpDests[dest.Uint64()] {
			return nil, ErrInvalidJump
		}
		i.pc = dest.Uint64() - 1 // -1 because we increment at end of loop

	case JUMPI:
		dest, cond := i.stack.Pop(), i.stack.Pop()
		if cond.Sign() != 0 {
			if !i.jumpDests[dest.Uint64()] {
				return nil, ErrInvalidJump
			}
			i.pc = dest.Uint64() - 1
		}

	case PC:
		i.stack.Push(big.NewInt(int64(i.pc)))

	case MSIZE:
		i.stack.Push(big.NewInt(int64(i.memory.Len())))

	case GAS:
		i.stack.Push(big.NewInt(int64(i.gas)))

	case JUMPDEST:
		// Just a marker, no operation

	case PUSH0:
		i.stack.Push(big.NewInt(0))

	case PUSH1, PUSH2, PUSH3, PUSH4, PUSH5, PUSH6, PUSH7, PUSH8,
		PUSH9, PUSH10, PUSH11, PUSH12, PUSH13, PUSH14, PUSH15, PUSH16,
		PUSH17, PUSH18, PUSH19, PUSH20, PUSH21, PUSH22, PUSH23, PUSH24,
		PUSH25, PUSH26, PUSH27, PUSH28, PUSH29, PUSH30, PUSH31, PUSH32:
		size := int(op - PUSH1 + 1)
		data := make([]byte, size)
		for j := 0; j < size; j++ {
			if i.pc+1+uint64(j) < uint64(len(i.contract.Code)) {
				data[j] = i.contract.Code[i.pc+1+uint64(j)]
			}
		}
		i.stack.Push(new(big.Int).SetBytes(data))
		i.pc += uint64(size)

	case DUP1, DUP2, DUP3, DUP4, DUP5, DUP6, DUP7, DUP8,
		DUP9, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16:
		pos := int(op - DUP1)
		if err := i.stack.Dup(pos); err != nil {
			return nil, err
		}

	case SWAP1, SWAP2, SWAP3, SWAP4, SWAP5, SWAP6, SWAP7, SWAP8,
		SWAP9, SWAP10, SWAP11, SWAP12, SWAP13, SWAP14, SWAP15, SWAP16:
		pos := int(op - SWAP1 + 1)
		if err := i.stack.Swap(pos); err != nil {
			return nil, err
		}

	case LOG0, LOG1, LOG2, LOG3, LOG4:
		if i.readOnly {
			return nil, ErrWriteProtection
		}
		topicCount := int(op - LOG0)
		offset, size := i.stack.Pop(), i.stack.Pop()
		topics := make([]common.Hash, topicCount)
		for j := 0; j < topicCount; j++ {
			topics[j] = common.BigToHash(i.stack.Pop())
		}
		if err := i.useGasForMemory(offset.Uint64(), size.Uint64()); err != nil {
			return nil, err
		}
		data := i.memory.GetCopy(offset.Uint64(), size.Uint64())
		i.logs = append(i.logs, &Log{
			Address: i.contract.Address,
			Topics:  topics,
			Data:    data,
		})

	case CREATE:
		if i.readOnly {
			return nil, ErrWriteProtection
		}
		value, offset, size := i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		if err := i.useGasForMemory(offset.Uint64(), size.Uint64()); err != nil {
			return nil, err
		}
		input := i.memory.GetCopy(offset.Uint64(), size.Uint64())
		addr := i.create(value, input, i.gas, nil)
		i.stack.Push(new(big.Int).SetBytes(addr.Bytes()))

	case CALL:
		gas, addr, value := i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		inOffset, inSize, outOffset, outSize := i.stack.Pop(), i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		toAddr := common.BigToAddress(addr)

		if err := i.useGasForMemory(inOffset.Uint64(), inSize.Uint64()); err != nil {
			return nil, err
		}
		if err := i.useGasForMemory(outOffset.Uint64(), outSize.Uint64()); err != nil {
			return nil, err
		}

		input := i.memory.GetCopy(inOffset.Uint64(), inSize.Uint64())
		ret, success := i.call(gas.Uint64(), toAddr, value, input)
		i.returnData = ret

		if success {
			i.stack.Push(big.NewInt(1))
		} else {
			i.stack.Push(big.NewInt(0))
		}

		if len(ret) > 0 && outSize.Uint64() > 0 {
			copySize := outSize.Uint64()
			if uint64(len(ret)) < copySize {
				copySize = uint64(len(ret))
			}
			i.memory.Set(outOffset.Uint64(), copySize, ret[:copySize])
		}

	case CALLCODE:
		gas, addr, value := i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		inOffset, inSize, outOffset, outSize := i.stack.Pop(), i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		toAddr := common.BigToAddress(addr)

		if err := i.useGasForMemory(inOffset.Uint64(), inSize.Uint64()); err != nil {
			return nil, err
		}
		if err := i.useGasForMemory(outOffset.Uint64(), outSize.Uint64()); err != nil {
			return nil, err
		}

		input := i.memory.GetCopy(inOffset.Uint64(), inSize.Uint64())
		ret, success := i.callCode(gas.Uint64(), toAddr, value, input)
		i.returnData = ret

		if success {
			i.stack.Push(big.NewInt(1))
		} else {
			i.stack.Push(big.NewInt(0))
		}

		if len(ret) > 0 && outSize.Uint64() > 0 {
			copySize := outSize.Uint64()
			if uint64(len(ret)) < copySize {
				copySize = uint64(len(ret))
			}
			i.memory.Set(outOffset.Uint64(), copySize, ret[:copySize])
		}

	case RETURN:
		offset, size := i.stack.Pop(), i.stack.Pop()
		if err := i.useGasForMemory(offset.Uint64(), size.Uint64()); err != nil {
			return nil, err
		}
		return i.memory.GetCopy(offset.Uint64(), size.Uint64()), nil

	case DELEGATECALL:
		gas, addr := i.stack.Pop(), i.stack.Pop()
		inOffset, inSize, outOffset, outSize := i.stack.Pop(), i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		toAddr := common.BigToAddress(addr)

		if err := i.useGasForMemory(inOffset.Uint64(), inSize.Uint64()); err != nil {
			return nil, err
		}
		if err := i.useGasForMemory(outOffset.Uint64(), outSize.Uint64()); err != nil {
			return nil, err
		}

		input := i.memory.GetCopy(inOffset.Uint64(), inSize.Uint64())
		ret, success := i.delegateCall(gas.Uint64(), toAddr, input)
		i.returnData = ret

		if success {
			i.stack.Push(big.NewInt(1))
		} else {
			i.stack.Push(big.NewInt(0))
		}

		if len(ret) > 0 && outSize.Uint64() > 0 {
			copySize := outSize.Uint64()
			if uint64(len(ret)) < copySize {
				copySize = uint64(len(ret))
			}
			i.memory.Set(outOffset.Uint64(), copySize, ret[:copySize])
		}

	case CREATE2:
		if i.readOnly {
			return nil, ErrWriteProtection
		}
		value, offset, size, salt := i.stack.Pop(), i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		if err := i.useGasForMemory(offset.Uint64(), size.Uint64()); err != nil {
			return nil, err
		}
		input := i.memory.GetCopy(offset.Uint64(), size.Uint64())
		addr := i.create(value, input, i.gas, salt)
		i.stack.Push(new(big.Int).SetBytes(addr.Bytes()))

	case STATICCALL:
		gas, addr := i.stack.Pop(), i.stack.Pop()
		inOffset, inSize, outOffset, outSize := i.stack.Pop(), i.stack.Pop(), i.stack.Pop(), i.stack.Pop()
		toAddr := common.BigToAddress(addr)

		if err := i.useGasForMemory(inOffset.Uint64(), inSize.Uint64()); err != nil {
			return nil, err
		}
		if err := i.useGasForMemory(outOffset.Uint64(), outSize.Uint64()); err != nil {
			return nil, err
		}

		input := i.memory.GetCopy(inOffset.Uint64(), inSize.Uint64())
		ret, success := i.staticCall(gas.Uint64(), toAddr, input)
		i.returnData = ret

		if success {
			i.stack.Push(big.NewInt(1))
		} else {
			i.stack.Push(big.NewInt(0))
		}

		if len(ret) > 0 && outSize.Uint64() > 0 {
			copySize := outSize.Uint64()
			if uint64(len(ret)) < copySize {
				copySize = uint64(len(ret))
			}
			i.memory.Set(outOffset.Uint64(), copySize, ret[:copySize])
		}

	case REVERT:
		offset, size := i.stack.Pop(), i.stack.Pop()
		if err := i.useGasForMemory(offset.Uint64(), size.Uint64()); err != nil {
			return nil, err
		}
		i.returnData = i.memory.GetCopy(offset.Uint64(), size.Uint64())
		return nil, errors.New("execution reverted")

	case INVALID:
		return nil, ErrInvalidOpcode

	case SELFDESTRUCT:
		if i.readOnly {
			return nil, ErrWriteProtection
		}
		beneficiary := common.BigToAddress(i.stack.Pop())
		balance := i.state.GetBalance(i.contract.Address)
		i.state.AddBalance(beneficiary, balance)
		i.state.SelfDestruct(i.contract.Address)
		return []byte{}, nil

	default:
		return nil, ErrInvalidOpcode
	}

	return nil, nil
}

// useGasForMemory charges gas for memory expansion
func (i *Interpreter) useGasForMemory(offset, size uint64) error {
	if size == 0 {
		return nil
	}
	newSize := offset + size
	cost := CalcMemoryCost(i.memory.Len(), newSize)
	if i.gas < cost {
		return ErrOutOfGas
	}
	i.gas -= cost
	return nil
}

// create deploys a new contract
func (i *Interpreter) create(value *big.Int, input []byte, gas uint64, salt *big.Int) common.Address {
	if i.depth >= 1024 {
		return common.Address{}
	}

	// Calculate address
	var addr common.Address
	if salt == nil {
		nonce := i.state.GetNonce(i.contract.Address)
		addr = crypto.CreateAddress(i.contract.Address, nonce)
		i.state.SetNonce(i.contract.Address, nonce+1)
	} else {
		codeHash := crypto.Keccak256Hash(input)
		addr = crypto.CreateAddress2(i.contract.Address, common.BigToHash(salt), codeHash.Bytes())
	}

	// Transfer value
	if value != nil && value.Sign() > 0 {
		if i.state.GetBalance(i.contract.Address).Cmp(value) < 0 {
			return common.Address{}
		}
		i.state.SubBalance(i.contract.Address, value)
		i.state.AddBalance(addr, value)
	}

	// Create account
	i.state.CreateAccount(addr)

	// Execute init code
	subInterpreter := NewInterpreter(i.state, i.ctx)
	subInterpreter.depth = i.depth + 1
	contract := &Contract{
		Caller:  i.contract.Address,
		Address: addr,
		Value:   value,
		Code:    input,
		Gas:     gas,
	}
	result := subInterpreter.Execute(contract, nil, false)

	if result.Err != nil {
		return common.Address{}
	}

	// Store deployed code
	i.state.SetCode(addr, result.ReturnData)

	return addr
}

// call executes a contract call
func (i *Interpreter) call(gas uint64, to common.Address, value *big.Int, input []byte) ([]byte, bool) {
	if i.depth >= 1024 {
		return nil, false
	}

	// Check for precompiled contract first
	if IsPrecompile(to) {
		ret, _, err := RunPrecompile(to, input, gas)
		return ret, err == nil
	}

	// Transfer value
	if value != nil && value.Sign() > 0 {
		if i.readOnly {
			return nil, false
		}
		if i.state.GetBalance(i.contract.Address).Cmp(value) < 0 {
			return nil, false
		}
		i.state.SubBalance(i.contract.Address, value)
		i.state.AddBalance(to, value)
	}

	code := i.state.GetCode(to)
	if len(code) == 0 {
		return nil, true
	}

	// Execute
	subInterpreter := NewInterpreter(i.state, i.ctx)
	subInterpreter.depth = i.depth + 1
	contract := &Contract{
		Caller:  i.contract.Address,
		Address: to,
		Value:   value,
		Code:    code,
		Gas:     gas,
	}
	result := subInterpreter.Execute(contract, input, i.readOnly)

	return result.ReturnData, result.Err == nil
}

// callCode executes code in the context of the current contract
func (i *Interpreter) callCode(gas uint64, to common.Address, value *big.Int, input []byte) ([]byte, bool) {
	if i.depth >= 1024 {
		return nil, false
	}

	// Check for precompiled contract first
	if IsPrecompile(to) {
		ret, _, err := RunPrecompile(to, input, gas)
		return ret, err == nil
	}

	code := i.state.GetCode(to)
	if len(code) == 0 {
		return nil, true
	}

	// Execute in current context
	subInterpreter := NewInterpreter(i.state, i.ctx)
	subInterpreter.depth = i.depth + 1
	contract := &Contract{
		Caller:  i.contract.Caller,
		Address: i.contract.Address, // Execute in current contract's context
		Value:   value,
		Code:    code,
		Gas:     gas,
	}
	result := subInterpreter.Execute(contract, input, i.readOnly)

	return result.ReturnData, result.Err == nil
}

// delegateCall executes code in the full context of the current contract
func (i *Interpreter) delegateCall(gas uint64, to common.Address, input []byte) ([]byte, bool) {
	if i.depth >= 1024 {
		return nil, false
	}

	code := i.state.GetCode(to)
	if len(code) == 0 {
		return nil, true
	}

	// Execute in current context with original caller and value
	subInterpreter := NewInterpreter(i.state, i.ctx)
	subInterpreter.depth = i.depth + 1
	contract := &Contract{
		Caller:  i.contract.Caller,
		Address: i.contract.Address,
		Value:   i.contract.Value,
		Code:    code,
		Gas:     gas,
	}
	result := subInterpreter.Execute(contract, input, i.readOnly)

	return result.ReturnData, result.Err == nil
}

// staticCall executes a read-only call
func (i *Interpreter) staticCall(gas uint64, to common.Address, input []byte) ([]byte, bool) {
	if i.depth >= 1024 {
		return nil, false
	}

	// Check for precompiled contract first
	if IsPrecompile(to) {
		ret, _, err := RunPrecompile(to, input, gas)
		return ret, err == nil
	}

	code := i.state.GetCode(to)
	if len(code) == 0 {
		return nil, true
	}

	// Execute read-only
	subInterpreter := NewInterpreter(i.state, i.ctx)
	subInterpreter.depth = i.depth + 1
	contract := &Contract{
		Caller:  i.contract.Address,
		Address: to,
		Value:   big.NewInt(0),
		Code:    code,
		Gas:     gas,
	}
	result := subInterpreter.Execute(contract, input, true) // Force read-only

	return result.ReturnData, result.Err == nil
}

// GetLogs returns logs generated during execution
func (i *Interpreter) GetLogs() []*Log {
	return i.logs
}

// Helper constants
var (
	tt256   = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	tt256m1 = new(big.Int).Sub(tt256, big.NewInt(1))
	tt255   = new(big.Int).Exp(big.NewInt(2), big.NewInt(255), nil)
)

// Helper functions
func signedDiv(x, y *big.Int) *big.Int {
	if y.Sign() == 0 {
		return big.NewInt(0)
	}
	n := toSigned(x)
	d := toSigned(y)
	return toUnsigned(new(big.Int).Div(n, d))
}

func signedMod(x, y *big.Int) *big.Int {
	if y.Sign() == 0 {
		return big.NewInt(0)
	}
	n := toSigned(x)
	d := toSigned(y)
	return toUnsigned(new(big.Int).Mod(n, d))
}

func signedCmp(x, y *big.Int) int {
	return toSigned(x).Cmp(toSigned(y))
}

func toSigned(x *big.Int) *big.Int {
	if x.Cmp(tt255) >= 0 {
		return new(big.Int).Sub(x, tt256)
	}
	return x
}

func toUnsigned(x *big.Int) *big.Int {
	if x.Sign() < 0 {
		return new(big.Int).Add(x, tt256)
	}
	return x
}

func signExtend(back, num *big.Int) *big.Int {
	if back.Cmp(big.NewInt(31)) >= 0 {
		return num
	}
	bit := uint(back.Uint64()*8 + 7)
	mask := new(big.Int).Lsh(big.NewInt(1), bit)
	mask.Sub(mask, big.NewInt(1))
	if num.Bit(int(bit)) == 1 {
		num.Or(num, new(big.Int).Xor(mask, tt256m1))
	} else {
		num.And(num, mask)
	}
	return num
}

func signedRightShift(value, shift *big.Int) *big.Int {
	if shift.Cmp(big.NewInt(256)) >= 0 {
		if value.Cmp(tt255) >= 0 {
			return tt256m1
		}
		return big.NewInt(0)
	}
	signed := toSigned(value)
	result := new(big.Int).Rsh(signed, uint(shift.Uint64()))
	return toUnsigned(result)
}

func getDataBig(data []byte, offset, length *big.Int) []byte {
	if length.Sign() == 0 {
		return nil
	}
	end := new(big.Int).Add(offset, length)
	result := make([]byte, length.Uint64())
	start := offset.Uint64()
	for i := uint64(0); i < length.Uint64(); i++ {
		if start+i < uint64(len(data)) {
			result[i] = data[start+i]
		}
	}
	_ = end
	return result
}
