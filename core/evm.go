package core

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/nanopy/nanopy-turbo/evm"
)

// EVMConfig holds EVM configuration
type EVMConfig struct {
	ChainID  *big.Int
	GasLimit uint64
}

// TurboEVM is the main EVM implementation for NanoPy Turbo L2
// Uses our Pure Go EVM interpreter with custom StateDB
type TurboEVM struct {
	config      *EVMConfig
	state       *StateDB
	header      *BlockHeader
	coinbase    common.Address
	gasUsed     uint64
	logs        []*Log
	interpreter *evm.Interpreter
	ctx         *evm.Context
}

// NewTurboEVM creates a new EVM instance
func NewTurboEVM(config *EVMConfig, state *StateDB, header *BlockHeader, coinbase common.Address) *TurboEVM {
	ctx := &evm.Context{
		Origin:      common.Address{}, // Set by caller
		GasPrice:    big.NewInt(1000000000),
		Coinbase:    coinbase,
		GasLimit:    config.GasLimit,
		BlockNumber: header.Number,
		Time:        header.Timestamp,
		Difficulty:  big.NewInt(0), // PoS
		BaseFee:     big.NewInt(1000000000),
		ChainID:     config.ChainID,
	}

	return &TurboEVM{
		config:      config,
		state:       state,
		header:      header,
		coinbase:    coinbase,
		logs:        make([]*Log, 0),
		ctx:         ctx,
		interpreter: evm.NewInterpreter(state, ctx),
	}
}

// SetOrigin sets the transaction origin
func (e *TurboEVM) SetOrigin(origin common.Address) {
	e.ctx.Origin = origin
}

// SetGasPrice sets the gas price
func (e *TurboEVM) SetGasPrice(gasPrice *big.Int) {
	e.ctx.GasPrice = gasPrice
}

// Transfer performs a value transfer between accounts
func (e *TurboEVM) Transfer(from, to common.Address, value *big.Int) error {
	if value == nil || value.Sign() == 0 {
		return nil
	}

	fromBalance := e.state.GetBalance(from)
	if fromBalance.Cmp(value) < 0 {
		return errors.New("insufficient balance for transfer")
	}

	e.state.SubBalance(from, value)
	e.state.AddBalance(to, value)
	return nil
}

// Create deploys a new contract
func (e *TurboEVM) Create(caller common.Address, code []byte, gas uint64, value *big.Int) (common.Address, []byte, uint64, error) {
	// Calculate contract address
	nonce := e.state.GetNonce(caller)
	contractAddr := crypto.CreateAddress(caller, nonce)

	// Increment nonce
	e.state.SetNonce(caller, nonce+1)

	// Transfer value to contract if any
	if value != nil && value.Sign() > 0 {
		if err := e.Transfer(caller, contractAddr, value); err != nil {
			return common.Address{}, nil, gas, err
		}
	}

	// Create the contract account
	e.state.CreateAccount(contractAddr)

	// Execute init code using our Pure Go interpreter
	contract := &evm.Contract{
		Caller:  caller,
		Address: contractAddr,
		Value:   value,
		Code:    code,
		Gas:     gas,
	}

	result := e.interpreter.Execute(contract, nil, false)

	if result.Err != nil {
		// Revert on error
		return common.Address{}, nil, result.GasUsed, result.Err
	}

	// Store the deployed bytecode (return data from init code)
	if len(result.ReturnData) > 0 {
		e.state.SetCode(contractAddr, result.ReturnData)
	}

	// Collect logs
	for _, log := range e.interpreter.GetLogs() {
		e.logs = append(e.logs, &Log{
			Address:     log.Address,
			Topics:      log.Topics,
			Data:        log.Data,
			BlockNumber: e.header.Number.Uint64(),
		})
	}

	e.gasUsed += result.GasUsed

	return contractAddr, result.ReturnData, result.GasUsed, nil
}

// Create2 deploys a new contract with CREATE2
func (e *TurboEVM) Create2(caller common.Address, code []byte, gas uint64, value *big.Int, salt *big.Int) (common.Address, []byte, uint64, error) {
	// Calculate CREATE2 address
	codeHash := crypto.Keccak256Hash(code)
	contractAddr := crypto.CreateAddress2(caller, common.BigToHash(salt), codeHash.Bytes())

	// Transfer value to contract if any
	if value != nil && value.Sign() > 0 {
		if err := e.Transfer(caller, contractAddr, value); err != nil {
			return common.Address{}, nil, gas, err
		}
	}

	// Create the contract account
	e.state.CreateAccount(contractAddr)

	// Execute init code
	contract := &evm.Contract{
		Caller:  caller,
		Address: contractAddr,
		Value:   value,
		Code:    code,
		Gas:     gas,
	}

	result := e.interpreter.Execute(contract, nil, false)

	if result.Err != nil {
		return common.Address{}, nil, result.GasUsed, result.Err
	}

	// Store deployed bytecode
	if len(result.ReturnData) > 0 {
		e.state.SetCode(contractAddr, result.ReturnData)
	}

	// Collect logs
	for _, log := range e.interpreter.GetLogs() {
		e.logs = append(e.logs, &Log{
			Address:     log.Address,
			Topics:      log.Topics,
			Data:        log.Data,
			BlockNumber: e.header.Number.Uint64(),
		})
	}

	e.gasUsed += result.GasUsed

	return contractAddr, result.ReturnData, result.GasUsed, nil
}

// Call executes a contract call or simple transfer
func (e *TurboEVM) Call(caller, to common.Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	// Transfer value first
	if value != nil && value.Sign() > 0 {
		if err := e.Transfer(caller, to, value); err != nil {
			return nil, gas, err
		}
	}

	// Check if it's a contract
	code := e.state.GetCode(to)
	if len(code) == 0 {
		// Simple transfer, use base gas
		gasUsed := uint64(21000)
		e.gasUsed += gasUsed
		return nil, gasUsed, nil
	}

	// Contract call - execute bytecode with Pure Go interpreter
	contract := &evm.Contract{
		Caller:  caller,
		Address: to,
		Value:   value,
		Code:    code,
		Gas:     gas,
	}

	result := e.interpreter.Execute(contract, input, false)

	// Collect logs
	for _, log := range e.interpreter.GetLogs() {
		e.logs = append(e.logs, &Log{
			Address:     log.Address,
			Topics:      log.Topics,
			Data:        log.Data,
			BlockNumber: e.header.Number.Uint64(),
		})
	}

	e.gasUsed += result.GasUsed

	return result.ReturnData, result.GasUsed, result.Err
}

// StaticCall executes a read-only call
func (e *TurboEVM) StaticCall(caller, to common.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	code := e.state.GetCode(to)
	if len(code) == 0 {
		return nil, 21000, nil
	}

	// Execute with read-only flag
	contract := &evm.Contract{
		Caller:  caller,
		Address: to,
		Value:   big.NewInt(0),
		Code:    code,
		Gas:     gas,
	}

	result := e.interpreter.Execute(contract, input, true) // Read-only

	return result.ReturnData, result.GasUsed, result.Err
}

// DelegateCall executes code in the context of the calling contract
func (e *TurboEVM) DelegateCall(caller, to common.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	code := e.state.GetCode(to)
	if len(code) == 0 {
		return nil, 21000, nil
	}

	// Execute in caller's context
	contract := &evm.Contract{
		Caller:  caller,
		Address: caller, // Use caller's address for storage
		Value:   big.NewInt(0),
		Code:    code,
		Gas:     gas,
	}

	result := e.interpreter.Execute(contract, input, false)

	// Collect logs
	for _, log := range e.interpreter.GetLogs() {
		e.logs = append(e.logs, &Log{
			Address:     log.Address,
			Topics:      log.Topics,
			Data:        log.Data,
			BlockNumber: e.header.Number.Uint64(),
		})
	}

	e.gasUsed += result.GasUsed

	return result.ReturnData, result.GasUsed, result.Err
}

// GetLogs returns logs generated during execution
func (e *TurboEVM) GetLogs() []*Log {
	return e.logs
}

// EmitLog adds a log entry
func (e *TurboEVM) EmitLog(addr common.Address, topics []common.Hash, data []byte) {
	log := &Log{
		Address:     addr,
		Topics:      topics,
		Data:        data,
		BlockNumber: e.header.Number.Uint64(),
	}
	e.logs = append(e.logs, log)
}

// GasUsed returns total gas used
func (e *TurboEVM) GasUsed() uint64 {
	return e.gasUsed
}

// ExecuteTransaction executes a transaction with the TurboEVM
func ExecuteTransaction(bc *Blockchain, tx *Transaction, header *BlockHeader, coinbase common.Address) (*Receipt, error) {
	from := tx.From()
	if from == (common.Address{}) {
		return nil, errors.New("invalid sender")
	}

	state := bc.State()

	// Check nonce
	expectedNonce := state.GetNonce(from)
	if tx.Nonce != expectedNonce {
		return nil, errors.New("invalid nonce")
	}

	// Calculate gas cost
	gasLimit := tx.GasLimit
	gasPrice := tx.GasPrice
	if gasPrice == nil {
		gasPrice = big.NewInt(1000000000) // 1 Gwei default
	}
	gasCost := new(big.Int).Mul(gasPrice, big.NewInt(int64(gasLimit)))

	// Check balance for gas + value
	value := tx.Value
	if value == nil {
		value = big.NewInt(0)
	}
	totalCost := new(big.Int).Add(gasCost, value)

	if state.GetBalance(from).Cmp(totalCost) < 0 {
		return nil, errors.New("insufficient balance")
	}

	// Deduct gas upfront
	state.SubBalance(from, gasCost)
	state.SetNonce(from, tx.Nonce+1)

	// Create EVM instance
	evmConfig := &EVMConfig{
		ChainID:  bc.Config().ChainID,
		GasLimit: header.GasLimit,
	}
	evm := NewTurboEVM(evmConfig, state, header, coinbase)
	evm.SetOrigin(from)
	evm.SetGasPrice(gasPrice)

	var (
		gasUsed      uint64
		contractAddr common.Address
		err          error
		returnData   []byte
	)

	if tx.To == nil {
		// Contract creation
		contractAddr, returnData, gasUsed, err = evm.Create(from, tx.Data, gasLimit, value)
		_ = returnData
	} else {
		// Call
		_, gasUsed, err = evm.Call(from, *tx.To, tx.Data, gasLimit, value)
	}

	// Refund unused gas
	if gasUsed < gasLimit {
		gasRefund := new(big.Int).Mul(gasPrice, big.NewInt(int64(gasLimit-gasUsed)))
		state.AddBalance(from, gasRefund)
	}

	// Pay coinbase (miner/sequencer reward)
	fee := new(big.Int).Mul(gasPrice, big.NewInt(int64(gasUsed)))
	state.AddBalance(coinbase, fee)

	// Create receipt
	status := uint64(1)
	if err != nil {
		status = 0
	}

	receipt := &Receipt{
		TxHash:          tx.Hash(),
		BlockNumber:     header.Number,
		From:            from,
		GasUsed:         gasUsed,
		CumulativeGas:   gasUsed,
		Status:          status,
		ContractAddress: contractAddr,
		Logs:            evm.GetLogs(),
	}

	if tx.To != nil {
		receipt.To = *tx.To
	}

	return receipt, nil
}
