package evm

// OpCode represents an EVM opcode
type OpCode byte

// EVM Opcodes - Complete set
const (
	// 0x0 range - arithmetic ops
	STOP       OpCode = 0x00
	ADD        OpCode = 0x01
	MUL        OpCode = 0x02
	SUB        OpCode = 0x03
	DIV        OpCode = 0x04
	SDIV       OpCode = 0x05
	MOD        OpCode = 0x06
	SMOD       OpCode = 0x07
	ADDMOD     OpCode = 0x08
	MULMOD     OpCode = 0x09
	EXP        OpCode = 0x0A
	SIGNEXTEND OpCode = 0x0B

	// 0x10 range - comparison ops
	LT     OpCode = 0x10
	GT     OpCode = 0x11
	SLT    OpCode = 0x12
	SGT    OpCode = 0x13
	EQ     OpCode = 0x14
	ISZERO OpCode = 0x15
	AND    OpCode = 0x16
	OR     OpCode = 0x17
	XOR    OpCode = 0x18
	NOT    OpCode = 0x19
	BYTE   OpCode = 0x1A
	SHL    OpCode = 0x1B
	SHR    OpCode = 0x1C
	SAR    OpCode = 0x1D

	// 0x20 range - crypto
	KECCAK256 OpCode = 0x20

	// 0x30 range - closure state
	ADDRESS        OpCode = 0x30
	BALANCE        OpCode = 0x31
	ORIGIN         OpCode = 0x32
	CALLER         OpCode = 0x33
	CALLVALUE      OpCode = 0x34
	CALLDATALOAD   OpCode = 0x35
	CALLDATASIZE   OpCode = 0x36
	CALLDATACOPY   OpCode = 0x37
	CODESIZE       OpCode = 0x38
	CODECOPY       OpCode = 0x39
	GASPRICE       OpCode = 0x3A
	EXTCODESIZE    OpCode = 0x3B
	EXTCODECOPY    OpCode = 0x3C
	RETURNDATASIZE OpCode = 0x3D
	RETURNDATACOPY OpCode = 0x3E
	EXTCODEHASH    OpCode = 0x3F

	// 0x40 range - block operations
	BLOCKHASH   OpCode = 0x40
	COINBASE    OpCode = 0x41
	TIMESTAMP   OpCode = 0x42
	NUMBER      OpCode = 0x43
	PREVRANDAO  OpCode = 0x44 // Was DIFFICULTY
	GASLIMIT    OpCode = 0x45
	CHAINID     OpCode = 0x46
	SELFBALANCE OpCode = 0x47
	BASEFEE     OpCode = 0x48

	// 0x50 range - storage and execution
	POP      OpCode = 0x50
	MLOAD    OpCode = 0x51
	MSTORE   OpCode = 0x52
	MSTORE8  OpCode = 0x53
	SLOAD    OpCode = 0x54
	SSTORE   OpCode = 0x55
	JUMP     OpCode = 0x56
	JUMPI    OpCode = 0x57
	PC       OpCode = 0x58
	MSIZE    OpCode = 0x59
	GAS      OpCode = 0x5A
	JUMPDEST OpCode = 0x5B
	TLOAD    OpCode = 0x5C
	TSTORE   OpCode = 0x5D
	MCOPY    OpCode = 0x5E
	PUSH0    OpCode = 0x5F

	// 0x60 range - push
	PUSH1  OpCode = 0x60
	PUSH2  OpCode = 0x61
	PUSH3  OpCode = 0x62
	PUSH4  OpCode = 0x63
	PUSH5  OpCode = 0x64
	PUSH6  OpCode = 0x65
	PUSH7  OpCode = 0x66
	PUSH8  OpCode = 0x67
	PUSH9  OpCode = 0x68
	PUSH10 OpCode = 0x69
	PUSH11 OpCode = 0x6A
	PUSH12 OpCode = 0x6B
	PUSH13 OpCode = 0x6C
	PUSH14 OpCode = 0x6D
	PUSH15 OpCode = 0x6E
	PUSH16 OpCode = 0x6F
	PUSH17 OpCode = 0x70
	PUSH18 OpCode = 0x71
	PUSH19 OpCode = 0x72
	PUSH20 OpCode = 0x73
	PUSH21 OpCode = 0x74
	PUSH22 OpCode = 0x75
	PUSH23 OpCode = 0x76
	PUSH24 OpCode = 0x77
	PUSH25 OpCode = 0x78
	PUSH26 OpCode = 0x79
	PUSH27 OpCode = 0x7A
	PUSH28 OpCode = 0x7B
	PUSH29 OpCode = 0x7C
	PUSH30 OpCode = 0x7D
	PUSH31 OpCode = 0x7E
	PUSH32 OpCode = 0x7F

	// 0x80 range - dup
	DUP1  OpCode = 0x80
	DUP2  OpCode = 0x81
	DUP3  OpCode = 0x82
	DUP4  OpCode = 0x83
	DUP5  OpCode = 0x84
	DUP6  OpCode = 0x85
	DUP7  OpCode = 0x86
	DUP8  OpCode = 0x87
	DUP9  OpCode = 0x88
	DUP10 OpCode = 0x89
	DUP11 OpCode = 0x8A
	DUP12 OpCode = 0x8B
	DUP13 OpCode = 0x8C
	DUP14 OpCode = 0x8D
	DUP15 OpCode = 0x8E
	DUP16 OpCode = 0x8F

	// 0x90 range - swap
	SWAP1  OpCode = 0x90
	SWAP2  OpCode = 0x91
	SWAP3  OpCode = 0x92
	SWAP4  OpCode = 0x93
	SWAP5  OpCode = 0x94
	SWAP6  OpCode = 0x95
	SWAP7  OpCode = 0x96
	SWAP8  OpCode = 0x97
	SWAP9  OpCode = 0x98
	SWAP10 OpCode = 0x99
	SWAP11 OpCode = 0x9A
	SWAP12 OpCode = 0x9B
	SWAP13 OpCode = 0x9C
	SWAP14 OpCode = 0x9D
	SWAP15 OpCode = 0x9E
	SWAP16 OpCode = 0x9F

	// 0xA0 range - logging
	LOG0 OpCode = 0xA0
	LOG1 OpCode = 0xA1
	LOG2 OpCode = 0xA2
	LOG3 OpCode = 0xA3
	LOG4 OpCode = 0xA4

	// 0xF0 range - closures
	CREATE       OpCode = 0xF0
	CALL         OpCode = 0xF1
	CALLCODE     OpCode = 0xF2
	RETURN       OpCode = 0xF3
	DELEGATECALL OpCode = 0xF4
	CREATE2      OpCode = 0xF5
	STATICCALL   OpCode = 0xFA
	REVERT       OpCode = 0xFD
	INVALID      OpCode = 0xFE
	SELFDESTRUCT OpCode = 0xFF
)

// OpCodeInfo holds metadata for an opcode
type OpCodeInfo struct {
	Name       string
	StackPop   int
	StackPush  int
	Gas        uint64
	MemorySize int // -1 if dynamic
}

// OpcodeTable maps opcodes to their info
// OpCodeInfos is an alias for OpcodeTable
var OpcodeTable = map[OpCode]OpCodeInfo{
	STOP:       {"STOP", 0, 0, 0, 0},
	ADD:        {"ADD", 2, 1, 3, 0},
	MUL:        {"MUL", 2, 1, 5, 0},
	SUB:        {"SUB", 2, 1, 3, 0},
	DIV:        {"DIV", 2, 1, 5, 0},
	SDIV:       {"SDIV", 2, 1, 5, 0},
	MOD:        {"MOD", 2, 1, 5, 0},
	SMOD:       {"SMOD", 2, 1, 5, 0},
	ADDMOD:     {"ADDMOD", 3, 1, 8, 0},
	MULMOD:     {"MULMOD", 3, 1, 8, 0},
	EXP:        {"EXP", 2, 1, 10, 0}, // Dynamic
	SIGNEXTEND: {"SIGNEXTEND", 2, 1, 5, 0},

	LT:     {"LT", 2, 1, 3, 0},
	GT:     {"GT", 2, 1, 3, 0},
	SLT:    {"SLT", 2, 1, 3, 0},
	SGT:    {"SGT", 2, 1, 3, 0},
	EQ:     {"EQ", 2, 1, 3, 0},
	ISZERO: {"ISZERO", 1, 1, 3, 0},
	AND:    {"AND", 2, 1, 3, 0},
	OR:     {"OR", 2, 1, 3, 0},
	XOR:    {"XOR", 2, 1, 3, 0},
	NOT:    {"NOT", 1, 1, 3, 0},
	BYTE:   {"BYTE", 2, 1, 3, 0},
	SHL:    {"SHL", 2, 1, 3, 0},
	SHR:    {"SHR", 2, 1, 3, 0},
	SAR:    {"SAR", 2, 1, 3, 0},

	KECCAK256: {"KECCAK256", 2, 1, 30, -1},

	ADDRESS:        {"ADDRESS", 0, 1, 2, 0},
	BALANCE:        {"BALANCE", 1, 1, 100, 0}, // Cold: 2600
	ORIGIN:         {"ORIGIN", 0, 1, 2, 0},
	CALLER:         {"CALLER", 0, 1, 2, 0},
	CALLVALUE:      {"CALLVALUE", 0, 1, 2, 0},
	CALLDATALOAD:   {"CALLDATALOAD", 1, 1, 3, 0},
	CALLDATASIZE:   {"CALLDATASIZE", 0, 1, 2, 0},
	CALLDATACOPY:   {"CALLDATACOPY", 3, 0, 3, -1},
	CODESIZE:       {"CODESIZE", 0, 1, 2, 0},
	CODECOPY:       {"CODECOPY", 3, 0, 3, -1},
	GASPRICE:       {"GASPRICE", 0, 1, 2, 0},
	EXTCODESIZE:    {"EXTCODESIZE", 1, 1, 100, 0},
	EXTCODECOPY:    {"EXTCODECOPY", 4, 0, 100, -1},
	RETURNDATASIZE: {"RETURNDATASIZE", 0, 1, 2, 0},
	RETURNDATACOPY: {"RETURNDATACOPY", 3, 0, 3, -1},
	EXTCODEHASH:    {"EXTCODEHASH", 1, 1, 100, 0},

	BLOCKHASH:   {"BLOCKHASH", 1, 1, 20, 0},
	COINBASE:    {"COINBASE", 0, 1, 2, 0},
	TIMESTAMP:   {"TIMESTAMP", 0, 1, 2, 0},
	NUMBER:      {"NUMBER", 0, 1, 2, 0},
	PREVRANDAO:  {"PREVRANDAO", 0, 1, 2, 0},
	GASLIMIT:    {"GASLIMIT", 0, 1, 2, 0},
	CHAINID:     {"CHAINID", 0, 1, 2, 0},
	SELFBALANCE: {"SELFBALANCE", 0, 1, 5, 0},
	BASEFEE:     {"BASEFEE", 0, 1, 2, 0},

	POP:      {"POP", 1, 0, 2, 0},
	MLOAD:    {"MLOAD", 1, 1, 3, 0},
	MSTORE:   {"MSTORE", 2, 0, 3, 0},
	MSTORE8:  {"MSTORE8", 2, 0, 3, 0},
	SLOAD:    {"SLOAD", 1, 1, 100, 0}, // Cold: 2100
	SSTORE:   {"SSTORE", 2, 0, 100, 0}, // Dynamic
	JUMP:     {"JUMP", 1, 0, 8, 0},
	JUMPI:    {"JUMPI", 2, 0, 10, 0},
	PC:       {"PC", 0, 1, 2, 0},
	MSIZE:    {"MSIZE", 0, 1, 2, 0},
	GAS:      {"GAS", 0, 1, 2, 0},
	JUMPDEST: {"JUMPDEST", 0, 0, 1, 0},
	TLOAD:    {"TLOAD", 1, 1, 100, 0},
	TSTORE:   {"TSTORE", 2, 0, 100, 0},
	MCOPY:    {"MCOPY", 3, 0, 3, -1},
	PUSH0:    {"PUSH0", 0, 1, 2, 0},

	LOG0: {"LOG0", 2, 0, 375, -1},
	LOG1: {"LOG1", 3, 0, 750, -1},
	LOG2: {"LOG2", 4, 0, 1125, -1},
	LOG3: {"LOG3", 5, 0, 1500, -1},
	LOG4: {"LOG4", 6, 0, 1875, -1},

	CREATE:       {"CREATE", 3, 1, 32000, -1},
	CALL:         {"CALL", 7, 1, 100, -1},
	CALLCODE:     {"CALLCODE", 7, 1, 100, -1},
	RETURN:       {"RETURN", 2, 0, 0, -1},
	DELEGATECALL: {"DELEGATECALL", 6, 1, 100, -1},
	CREATE2:      {"CREATE2", 4, 1, 32000, -1},
	STATICCALL:   {"STATICCALL", 6, 1, 100, -1},
	REVERT:       {"REVERT", 2, 0, 0, -1},
	INVALID:      {"INVALID", 0, 0, 0, 0},
	SELFDESTRUCT: {"SELFDESTRUCT", 1, 0, 5000, 0},
}

func init() {
	// Add PUSH1-32 to table
	for i := 0; i < 32; i++ {
		op := OpCode(byte(PUSH1) + byte(i))
		OpcodeTable[op] = OpCodeInfo{
			Name:      "PUSH" + string(rune('1'+i)),
			StackPop:  0,
			StackPush: 1,
			Gas:       3,
		}
	}
	// Add DUP1-16 to table
	for i := 0; i < 16; i++ {
		op := OpCode(byte(DUP1) + byte(i))
		OpcodeTable[op] = OpCodeInfo{
			Name:      "DUP" + string(rune('1'+i)),
			StackPop:  i + 1,
			StackPush: i + 2,
			Gas:       3,
		}
	}
	// Add SWAP1-16 to table
	for i := 0; i < 16; i++ {
		op := OpCode(byte(SWAP1) + byte(i))
		OpcodeTable[op] = OpCodeInfo{
			Name:      "SWAP" + string(rune('1'+i)),
			StackPop:  i + 2,
			StackPush: i + 2,
			Gas:       3,
		}
	}
}

// String returns the opcode name
func (op OpCode) String() string {
	if info, ok := OpcodeTable[op]; ok {
		return info.Name
	}
	return "UNKNOWN"
}

// IsPush returns true if this is a PUSH opcode
func (op OpCode) IsPush() bool {
	return op >= PUSH1 && op <= PUSH32
}

// PushSize returns the number of bytes to push (0 if not a push)
func (op OpCode) PushSize() int {
	if op == PUSH0 {
		return 0
	}
	if op >= PUSH1 && op <= PUSH32 {
		return int(op - PUSH1 + 1)
	}
	return 0
}

// OpCodeInfos is an alias for OpcodeTable for compatibility
var OpCodeInfos = OpcodeTable
