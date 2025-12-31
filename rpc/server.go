package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/nanopy/nanopy-turbo/core"
)

// Server is the JSON-RPC server with HTTP and WebSocket support
type Server struct {
	bc       *core.Blockchain
	addr     string
	router   *mux.Router
	upgrader websocket.Upgrader

	// WebSocket subscriptions
	subMu       sync.RWMutex
	subscribers map[*websocket.Conn]map[string]bool // conn -> subscription IDs
	subCounter  uint64
}

// Request represents a JSON-RPC request
type Request struct {
	JSONRPC string            `json:"jsonrpc"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
	ID      interface{}       `json:"id"`
}

// Response represents a JSON-RPC response
type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// SubscriptionNotification represents a subscription notification
type SubscriptionNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

// RPCError represents a JSON-RPC error
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewServer creates a new RPC server
func NewServer(bc *core.Blockchain, addr string) *Server {
	s := &Server{
		bc:     bc,
		addr:   addr,
		router: mux.NewRouter(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins
			},
		},
		subscribers: make(map[*websocket.Conn]map[string]bool),
	}

	// HTTP routes
	s.router.HandleFunc("/", s.handleRPC).Methods("POST", "OPTIONS")
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")

	// WebSocket route
	s.router.HandleFunc("/ws", s.handleWebSocket)
	s.router.HandleFunc("/", s.handleWebSocket).Headers("Upgrade", "websocket")

	return s
}

// Start starts the RPC server
func (s *Server) Start() error {
	log.Printf("RPC server listening on %s (HTTP + WebSocket)", s.addr)
	return http.ListenAndServe(s.addr, s.corsMiddleware(s.router))
}

// corsMiddleware adds CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleHealth handles health check
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// Register connection
	s.subMu.Lock()
	s.subscribers[conn] = make(map[string]bool)
	s.subMu.Unlock()

	defer func() {
		s.subMu.Lock()
		delete(s.subscribers, conn)
		s.subMu.Unlock()
	}()

	log.Printf("WebSocket client connected")

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		var req Request
		if err := json.Unmarshal(message, &req); err != nil {
			s.wsWriteError(conn, nil, -32700, "Parse error")
			continue
		}

		result, rpcErr := s.dispatchWS(conn, &req)

		resp := Response{
			JSONRPC: "2.0",
			ID:      req.ID,
		}

		if rpcErr != nil {
			resp.Error = rpcErr
		} else {
			resp.Result = result
		}

		if err := conn.WriteJSON(resp); err != nil {
			log.Printf("WebSocket write error: %v", err)
			break
		}
	}
}

// wsWriteError writes an error to WebSocket
func (s *Server) wsWriteError(conn *websocket.Conn, id interface{}, code int, message string) {
	resp := Response{
		JSONRPC: "2.0",
		Error:   &RPCError{Code: code, Message: message},
		ID:      id,
	}
	conn.WriteJSON(resp)
}

// dispatchWS routes WebSocket method calls
func (s *Server) dispatchWS(conn *websocket.Conn, req *Request) (interface{}, *RPCError) {
	switch req.Method {
	case "eth_subscribe":
		return s.ethSubscribe(conn, req.Params)
	case "eth_unsubscribe":
		return s.ethUnsubscribe(conn, req.Params)
	default:
		// Fallback to regular dispatch
		return s.dispatch(req)
	}
}

// ethSubscribe handles subscription requests
func (s *Server) ethSubscribe(conn *websocket.Conn, params []json.RawMessage) (interface{}, *RPCError) {
	if len(params) < 1 {
		return nil, &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var subType string
	if err := json.Unmarshal(params[0], &subType); err != nil {
		return nil, &RPCError{Code: -32602, Message: "Invalid subscription type"}
	}

	s.subMu.Lock()
	s.subCounter++
	subID := hexutil.EncodeUint64(s.subCounter)

	if s.subscribers[conn] == nil {
		s.subscribers[conn] = make(map[string]bool)
	}
	s.subscribers[conn][subID] = true
	s.subMu.Unlock()

	log.Printf("New subscription: %s (type: %s)", subID, subType)

	// Start sending updates based on subscription type
	switch subType {
	case "newHeads":
		go s.subscribeNewHeads(conn, subID)
	case "newPendingTransactions":
		go s.subscribePendingTxs(conn, subID)
	case "logs":
		// Handle log subscriptions
		go s.subscribeLogs(conn, subID, params)
	}

	return subID, nil
}

// ethUnsubscribe handles unsubscribe requests
func (s *Server) ethUnsubscribe(conn *websocket.Conn, params []json.RawMessage) (interface{}, *RPCError) {
	if len(params) < 1 {
		return nil, &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var subID string
	if err := json.Unmarshal(params[0], &subID); err != nil {
		return nil, &RPCError{Code: -32602, Message: "Invalid subscription ID"}
	}

	s.subMu.Lock()
	if subs, ok := s.subscribers[conn]; ok {
		delete(subs, subID)
	}
	s.subMu.Unlock()

	log.Printf("Unsubscribed: %s", subID)
	return true, nil
}

// subscribeNewHeads sends new block headers to subscribers
func (s *Server) subscribeNewHeads(conn *websocket.Conn, subID string) {
	lastBlock := s.bc.CurrentBlock().Number().Uint64()

	for {
		s.subMu.RLock()
		subs, ok := s.subscribers[conn]
		if !ok || !subs[subID] {
			s.subMu.RUnlock()
			return
		}
		s.subMu.RUnlock()

		currentBlock := s.bc.CurrentBlock()
		if currentBlock.Number().Uint64() > lastBlock {
			lastBlock = currentBlock.Number().Uint64()

			notification := SubscriptionNotification{
				JSONRPC: "2.0",
				Method:  "eth_subscription",
				Params: map[string]interface{}{
					"subscription": subID,
					"result":       s.formatBlockHeader(currentBlock),
				},
			}

			if err := conn.WriteJSON(notification); err != nil {
				return
			}
		}

		// Poll every 100ms
		time.Sleep(100 * time.Millisecond)
	}
}

// subscribePendingTxs sends pending transactions to subscribers
func (s *Server) subscribePendingTxs(conn *websocket.Conn, subID string) {
	// Simplified: just send new tx hashes when they arrive
	// In production, would use event channels
}

// subscribeLogs sends logs matching filter to subscribers
func (s *Server) subscribeLogs(conn *websocket.Conn, subID string, params []json.RawMessage) {
	// Parse filter from params if provided
	// In production, would filter logs by address/topics
}

// formatBlockHeader formats a block header for subscription
func (s *Server) formatBlockHeader(block *core.Block) map[string]interface{} {
	return map[string]interface{}{
		"number":           hexutil.EncodeBig(block.Number()),
		"hash":             block.Hash().Hex(),
		"parentHash":       block.Header.ParentHash.Hex(),
		"nonce":            "0x0000000000000000",
		"sha3Uncles":       common.Hash{}.Hex(),
		"logsBloom":        "0x" + strings.Repeat("0", 512),
		"transactionsRoot": block.Header.TxRoot.Hex(),
		"stateRoot":        block.Header.StateRoot.Hex(),
		"receiptsRoot":     block.Header.ReceiptRoot.Hex(),
		"miner":            block.Header.Coinbase.Hex(),
		"difficulty":       "0x1",
		"extraData":        hexutil.Encode(block.Header.ExtraData),
		"gasLimit":         hexutil.EncodeUint64(block.Header.GasLimit),
		"gasUsed":          hexutil.EncodeUint64(block.Header.GasUsed),
		"timestamp":        hexutil.EncodeUint64(block.Header.Timestamp),
	}
}

// BroadcastNewBlock sends a new block to all newHeads subscribers
func (s *Server) BroadcastNewBlock(block *core.Block) {
	s.subMu.RLock()
	defer s.subMu.RUnlock()

	for conn, subs := range s.subscribers {
		for subID := range subs {
			notification := SubscriptionNotification{
				JSONRPC: "2.0",
				Method:  "eth_subscription",
				Params: map[string]interface{}{
					"subscription": subID,
					"result":       s.formatBlockHeader(block),
				},
			}
			conn.WriteJSON(notification)
		}
	}
}

// handleRPC handles JSON-RPC requests
func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, nil, -32700, "Parse error")
		return
	}

	// Handle batch requests
	if len(body) > 0 && body[0] == '[' {
		var reqs []Request
		if err := json.Unmarshal(body, &reqs); err != nil {
			s.writeError(w, nil, -32700, "Parse error")
			return
		}

		responses := make([]Response, len(reqs))
		for i, req := range reqs {
			result, rpcErr := s.dispatch(&req)
			responses[i] = Response{
				JSONRPC: "2.0",
				ID:      req.ID,
			}
			if rpcErr != nil {
				responses[i].Error = rpcErr
			} else {
				responses[i].Result = result
			}
		}
		json.NewEncoder(w).Encode(responses)
		return
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, nil, -32700, "Parse error")
		return
	}

	result, rpcErr := s.dispatch(&req)
	if rpcErr != nil {
		s.writeError(w, req.ID, rpcErr.Code, rpcErr.Message)
		return
	}

	resp := Response{
		JSONRPC: "2.0",
		Result:  result,
		ID:      req.ID,
	}
	json.NewEncoder(w).Encode(resp)
}

// writeError writes an error response
func (s *Server) writeError(w http.ResponseWriter, id interface{}, code int, message string) {
	resp := Response{
		JSONRPC: "2.0",
		Error:   &RPCError{Code: code, Message: message},
		ID:      id,
	}
	json.NewEncoder(w).Encode(resp)
}

// dispatch routes method calls
func (s *Server) dispatch(req *Request) (interface{}, *RPCError) {
	switch req.Method {
	// Chain methods
	case "eth_chainId":
		return s.ethChainID()
	case "eth_blockNumber":
		return s.ethBlockNumber()
	case "eth_getBlockByNumber":
		return s.ethGetBlockByNumber(req.Params)
	case "eth_getBlockByHash":
		return s.ethGetBlockByHash(req.Params)

	// Account methods
	case "eth_getBalance":
		return s.ethGetBalance(req.Params)
	case "eth_getTransactionCount":
		return s.ethGetTransactionCount(req.Params)
	case "eth_getCode":
		return s.ethGetCode(req.Params)
	case "eth_getStorageAt":
		return s.ethGetStorageAt(req.Params)

	// Transaction methods
	case "eth_sendRawTransaction":
		return s.ethSendRawTransaction(req.Params)
	case "eth_getTransactionByHash":
		return s.ethGetTransactionByHash(req.Params)
	case "eth_getTransactionReceipt":
		return s.ethGetTransactionReceipt(req.Params)
	case "eth_call":
		return s.ethCall(req.Params)
	case "eth_estimateGas":
		return s.ethEstimateGas(req.Params)
	case "eth_getLogs":
		return s.ethGetLogs(req.Params)

	// Gas methods
	case "eth_gasPrice":
		return s.ethGasPrice()
	case "eth_maxPriorityFeePerGas":
		return "0x3B9ACA00", nil // 1 Gwei
	case "eth_feeHistory":
		return s.ethFeeHistory(req.Params)

	// Network methods
	case "net_version":
		return s.netVersion()
	case "net_listening":
		return true, nil
	case "net_peerCount":
		return "0x0", nil

	// Web3 methods
	case "web3_clientVersion":
		return "NanoPyTurbo/1.0.0", nil
	case "web3_sha3":
		return s.web3Sha3(req.Params)

	// L2 Bridge / Withdrawal methods
	case "turbo_getWithdrawalProof":
		return s.turboGetWithdrawalProof(req.Params)
	case "turbo_getWithdrawalRoot":
		return s.turboGetWithdrawalRoot()
	case "turbo_getPendingWithdrawals":
		return s.turboGetPendingWithdrawals()
	case "turbo_getWithdrawal":
		return s.turboGetWithdrawal(req.Params)

	// Eth methods
	case "eth_syncing":
		return false, nil
	case "eth_coinbase":
		return s.bc.CurrentBlock().Header.Coinbase.Hex(), nil
	case "eth_accounts":
		return []string{}, nil
	case "eth_mining":
		return false, nil
	case "eth_hashrate":
		return "0x0", nil

	default:
		return nil, &RPCError{Code: -32601, Message: "Method not found: " + req.Method}
	}
}

// ethChainID returns the chain ID
func (s *Server) ethChainID() (string, *RPCError) {
	chainID := s.bc.Config().ChainID
	return hexutil.EncodeBig(chainID), nil
}

// netVersion returns the network ID
func (s *Server) netVersion() (string, *RPCError) {
	return s.bc.Config().ChainID.String(), nil
}

// ethBlockNumber returns the current block number
func (s *Server) ethBlockNumber() (string, *RPCError) {
	block := s.bc.CurrentBlock()
	return hexutil.EncodeBig(block.Number()), nil
}

// ethGasPrice returns the gas price
func (s *Server) ethGasPrice() (string, *RPCError) {
	// Fixed gas price: 1 Gwei
	return "0x3B9ACA00", nil
}

// ethGetBalance returns the balance of an address
func (s *Server) ethGetBalance(params []json.RawMessage) (string, *RPCError) {
	if len(params) < 1 {
		return "", &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var addrHex string
	if err := json.Unmarshal(params[0], &addrHex); err != nil {
		return "", &RPCError{Code: -32602, Message: "Invalid address"}
	}

	addr := common.HexToAddress(addrHex)
	balance := s.bc.State().GetBalance(addr)
	return hexutil.EncodeBig(balance), nil
}

// ethGetTransactionCount returns the nonce of an address
func (s *Server) ethGetTransactionCount(params []json.RawMessage) (string, *RPCError) {
	if len(params) < 1 {
		return "", &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var addrHex string
	if err := json.Unmarshal(params[0], &addrHex); err != nil {
		return "", &RPCError{Code: -32602, Message: "Invalid address"}
	}

	addr := common.HexToAddress(addrHex)
	nonce := s.bc.State().GetNonce(addr)
	return hexutil.EncodeUint64(nonce), nil
}

// ethGetCode returns the code of a contract
func (s *Server) ethGetCode(params []json.RawMessage) (string, *RPCError) {
	if len(params) < 1 {
		return "", &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var addrHex string
	if err := json.Unmarshal(params[0], &addrHex); err != nil {
		return "", &RPCError{Code: -32602, Message: "Invalid address"}
	}

	addr := common.HexToAddress(addrHex)
	code := s.bc.State().GetCode(addr)
	if len(code) == 0 {
		return "0x", nil
	}
	return hexutil.Encode(code), nil
}

// ethGetStorageAt returns storage at a position
func (s *Server) ethGetStorageAt(params []json.RawMessage) (string, *RPCError) {
	if len(params) < 2 {
		return "", &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var addrHex, posHex string
	json.Unmarshal(params[0], &addrHex)
	json.Unmarshal(params[1], &posHex)

	addr := common.HexToAddress(addrHex)
	pos := common.HexToHash(posHex)
	value := s.bc.State().GetStorage(addr, pos)
	return value.Hex(), nil
}

// ethGetBlockByNumber returns a block by number
func (s *Server) ethGetBlockByNumber(params []json.RawMessage) (interface{}, *RPCError) {
	if len(params) < 1 {
		return nil, &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var blockNumHex string
	json.Unmarshal(params[0], &blockNumHex)

	var blockNum uint64
	if blockNumHex == "latest" || blockNumHex == "pending" {
		blockNum = s.bc.CurrentBlock().Number().Uint64()
	} else if blockNumHex == "earliest" {
		blockNum = 0
	} else {
		blockNum = hexToUint64(blockNumHex)
	}

	block := s.bc.GetBlockByNumber(blockNum)
	if block == nil {
		return nil, nil
	}

	return s.formatBlock(block, len(params) > 1), nil
}

// ethGetBlockByHash returns a block by hash
func (s *Server) ethGetBlockByHash(params []json.RawMessage) (interface{}, *RPCError) {
	if len(params) < 1 {
		return nil, &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var hashHex string
	json.Unmarshal(params[0], &hashHex)

	hash := common.HexToHash(hashHex)
	block := s.bc.GetBlock(hash)
	if block == nil {
		return nil, nil
	}

	return s.formatBlock(block, len(params) > 1), nil
}

// formatBlock formats a block for JSON-RPC response
func (s *Server) formatBlock(block *core.Block, fullTx bool) map[string]interface{} {
	txs := make([]interface{}, len(block.Transactions))
	for i, tx := range block.Transactions {
		if fullTx {
			txs[i] = s.formatTransaction(tx, block)
		} else {
			txs[i] = tx.Hash().Hex()
		}
	}

	return map[string]interface{}{
		"number":           hexutil.EncodeBig(block.Number()),
		"hash":             block.Hash().Hex(),
		"parentHash":       block.Header.ParentHash.Hex(),
		"nonce":            "0x0000000000000000",
		"sha3Uncles":       common.Hash{}.Hex(),
		"logsBloom":        "0x" + strings.Repeat("0", 512),
		"transactionsRoot": block.Header.TxRoot.Hex(),
		"stateRoot":        block.Header.StateRoot.Hex(),
		"receiptsRoot":     block.Header.ReceiptRoot.Hex(),
		"miner":            block.Header.Coinbase.Hex(),
		"difficulty":       "0x1",
		"totalDifficulty":  "0x1",
		"extraData":        hexutil.Encode(block.Header.ExtraData),
		"size":             "0x0",
		"gasLimit":         hexutil.EncodeUint64(block.Header.GasLimit),
		"gasUsed":          hexutil.EncodeUint64(block.Header.GasUsed),
		"timestamp":        hexutil.EncodeUint64(block.Header.Timestamp),
		"transactions":     txs,
		"uncles":           []string{},
		"baseFeePerGas":    "0x3B9ACA00", // 1 Gwei
	}
}

// formatTransaction formats a transaction for JSON-RPC response
func (s *Server) formatTransaction(tx *core.Transaction, block *core.Block) map[string]interface{} {
	result := map[string]interface{}{
		"hash":             tx.Hash().Hex(),
		"nonce":            hexutil.EncodeUint64(tx.Nonce),
		"blockHash":        block.Hash().Hex(),
		"blockNumber":      hexutil.EncodeBig(block.Number()),
		"transactionIndex": "0x0",
		"from":             tx.From().Hex(),
		"value":            hexutil.EncodeBig(tx.Value),
		"gas":              hexutil.EncodeUint64(tx.GasLimit),
		"gasPrice":         hexutil.EncodeBig(tx.GasPrice),
		"input":            hexutil.Encode(tx.Data),
		"v":                hexutil.EncodeBig(tx.V),
		"r":                hexutil.EncodeBig(tx.R),
		"s":                hexutil.EncodeBig(tx.S),
		"type":             "0x0",
	}

	if tx.To != nil {
		result["to"] = tx.To.Hex()
	} else {
		result["to"] = nil
	}

	return result
}

// ethGetTransactionByHash returns a transaction by hash
func (s *Server) ethGetTransactionByHash(params []json.RawMessage) (interface{}, *RPCError) {
	if len(params) < 1 {
		return nil, &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var hashHex string
	json.Unmarshal(params[0], &hashHex)

	hash := common.HexToHash(hashHex)
	tx := s.bc.GetTransaction(hash)
	if tx == nil {
		return nil, nil
	}

	// Find block containing tx
	currentBlock := s.bc.CurrentBlock()
	return s.formatTransaction(tx, currentBlock), nil
}

// ethGetTransactionReceipt returns a transaction receipt
func (s *Server) ethGetTransactionReceipt(params []json.RawMessage) (interface{}, *RPCError) {
	if len(params) < 1 {
		return nil, &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var hashHex string
	json.Unmarshal(params[0], &hashHex)

	hash := common.HexToHash(hashHex)
	receipt := s.bc.GetReceipt(hash)
	if receipt == nil {
		return nil, nil
	}

	return s.formatReceipt(receipt), nil
}

// formatReceipt formats a receipt for JSON-RPC response
func (s *Server) formatReceipt(r *core.Receipt) map[string]interface{} {
	logs := make([]map[string]interface{}, len(r.Logs))
	for i, log := range r.Logs {
		topics := make([]string, len(log.Topics))
		for j, t := range log.Topics {
			topics[j] = t.Hex()
		}
		logs[i] = map[string]interface{}{
			"address":          log.Address.Hex(),
			"topics":           topics,
			"data":             hexutil.Encode(log.Data),
			"blockNumber":      hexutil.EncodeUint64(log.BlockNumber),
			"transactionHash":  log.TxHash.Hex(),
			"transactionIndex": hexutil.EncodeUint64(log.TxIndex),
			"blockHash":        log.BlockHash.Hex(),
			"logIndex":         hexutil.EncodeUint64(log.LogIndex),
			"removed":          false,
		}
	}

	result := map[string]interface{}{
		"transactionHash":   r.TxHash.Hex(),
		"transactionIndex":  hexutil.EncodeUint64(r.TransactionIdx),
		"blockHash":         r.BlockHash.Hex(),
		"blockNumber":       hexutil.EncodeBig(r.BlockNumber),
		"from":              r.From.Hex(),
		"to":                r.To.Hex(),
		"cumulativeGasUsed": hexutil.EncodeUint64(r.CumulativeGas),
		"gasUsed":           hexutil.EncodeUint64(r.GasUsed),
		"effectiveGasPrice": "0x3B9ACA00",
		"contractAddress":   nil,
		"logs":              logs,
		"logsBloom":         "0x" + strings.Repeat("0", 512),
		"status":            hexutil.EncodeUint64(r.Status),
		"type":              "0x0",
	}

	if r.ContractAddress != (common.Address{}) {
		result["contractAddress"] = r.ContractAddress.Hex()
	}

	return result
}

// ethSendRawTransaction submits a signed transaction
func (s *Server) ethSendRawTransaction(params []json.RawMessage) (string, *RPCError) {
	if len(params) < 1 {
		return "", &RPCError{Code: -32602, Message: "Missing or invalid parameters"}
	}

	var txHex string
	if err := json.Unmarshal(params[0], &txHex); err != nil {
		return "", &RPCError{Code: -32602, Message: "Invalid transaction hex"}
	}

	// Decode raw transaction bytes
	rawTxBytes := common.FromHex(txHex)
	if len(rawTxBytes) == 0 {
		return "", &RPCError{Code: -32602, Message: "Empty transaction data"}
	}

	// Decode the signed transaction
	tx, err := decodeRawTransaction(rawTxBytes, s.bc.Config().ChainID)
	if err != nil {
		log.Printf("Failed to decode raw transaction: %v", err)
		return "", &RPCError{Code: -32000, Message: "Failed to decode transaction: " + err.Error()}
	}

	log.Printf("Decoded tx: nonce=%d, to=%v, value=%s, gasLimit=%d, from=%s",
		tx.Nonce, tx.To, tx.Value.String(), tx.GasLimit, tx.From().Hex())

	if err := s.bc.AddTransaction(tx); err != nil {
		return "", &RPCError{Code: -32000, Message: err.Error()}
	}

	return tx.Hash().Hex(), nil
}

// decodeRawTransaction decodes RLP-encoded signed transaction
func decodeRawTransaction(data []byte, chainID *big.Int) (*core.Transaction, error) {
	// Check if it's a typed transaction (EIP-2718)
	if len(data) > 0 && data[0] < 0x80 {
		txType := data[0]
		switch txType {
		case 0x01:
			// EIP-2930 access list transaction
			return decodeEIP2930Transaction(data[1:], chainID)
		case 0x02:
			// EIP-1559 dynamic fee transaction
			return decodeEIP1559Transaction(data[1:], chainID)
		default:
			return nil, errors.New("unsupported transaction type")
		}
	}

	// Legacy transaction (type 0)
	return decodeLegacyTransaction(data, chainID)
}

// decodeLegacyTransaction decodes a legacy (type 0) transaction
func decodeLegacyTransaction(data []byte, chainID *big.Int) (*core.Transaction, error) {
	// Legacy transaction RLP: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
	var txData struct {
		Nonce    uint64
		GasPrice *big.Int
		GasLimit uint64
		To       *common.Address `rlp:"nil"` // nil for contract creation
		Value    *big.Int
		Data     []byte
		V        *big.Int
		R        *big.Int
		S        *big.Int
	}

	if err := rlp.DecodeBytes(data, &txData); err != nil {
		return nil, fmt.Errorf("failed to decode legacy tx: %w", err)
	}

	// Recover sender from signature
	signer, err := recoverSender(data, txData.V, txData.R, txData.S, chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to recover sender: %w", err)
	}

	tx := &core.Transaction{
		Nonce:    txData.Nonce,
		GasPrice: txData.GasPrice,
		GasLimit: txData.GasLimit,
		To:       txData.To,
		Value:    txData.Value,
		Data:     txData.Data,
		V:        txData.V,
		R:        txData.R,
		S:        txData.S,
	}
	tx.SetFrom(signer)

	return tx, nil
}

// decodeEIP2930Transaction decodes an EIP-2930 (type 1) transaction
func decodeEIP2930Transaction(data []byte, chainID *big.Int) (*core.Transaction, error) {
	// EIP-2930 RLP: [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, signatureYParity, signatureR, signatureS]
	var txData struct {
		ChainID    *big.Int
		Nonce      uint64
		GasPrice   *big.Int
		GasLimit   uint64
		To         *common.Address `rlp:"nil"`
		Value      *big.Int
		Data       []byte
		AccessList []struct {
			Address common.Address
			Keys    []common.Hash
		}
		V *big.Int
		R *big.Int
		S *big.Int
	}

	if err := rlp.DecodeBytes(data, &txData); err != nil {
		return nil, fmt.Errorf("failed to decode EIP-2930 tx: %w", err)
	}

	// For EIP-2930, V is just the y-parity (0 or 1)
	// Recover sender
	signer, err := recoverSenderEIP2930(data, txData.V, txData.R, txData.S)
	if err != nil {
		return nil, fmt.Errorf("failed to recover sender: %w", err)
	}

	tx := &core.Transaction{
		Nonce:    txData.Nonce,
		GasPrice: txData.GasPrice,
		GasLimit: txData.GasLimit,
		To:       txData.To,
		Value:    txData.Value,
		Data:     txData.Data,
		V:        txData.V,
		R:        txData.R,
		S:        txData.S,
	}
	tx.SetFrom(signer)

	return tx, nil
}

// decodeEIP1559Transaction decodes an EIP-1559 (type 2) transaction
func decodeEIP1559Transaction(data []byte, chainID *big.Int) (*core.Transaction, error) {
	// EIP-1559 RLP: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, signatureYParity, signatureR, signatureS]
	var txData struct {
		ChainID              *big.Int
		Nonce                uint64
		MaxPriorityFeePerGas *big.Int
		MaxFeePerGas         *big.Int
		GasLimit             uint64
		To                   *common.Address `rlp:"nil"`
		Value                *big.Int
		Data                 []byte
		AccessList           []struct {
			Address common.Address
			Keys    []common.Hash
		}
		V *big.Int
		R *big.Int
		S *big.Int
	}

	if err := rlp.DecodeBytes(data, &txData); err != nil {
		return nil, fmt.Errorf("failed to decode EIP-1559 tx: %w", err)
	}

	// Recover sender from EIP-1559 signature
	signer, err := recoverSenderEIP1559(data, txData.V, txData.R, txData.S)
	if err != nil {
		return nil, fmt.Errorf("failed to recover sender: %w", err)
	}

	// Use MaxFeePerGas as GasPrice for compatibility
	tx := &core.Transaction{
		Nonce:    txData.Nonce,
		GasPrice: txData.MaxFeePerGas,
		GasLimit: txData.GasLimit,
		To:       txData.To,
		Value:    txData.Value,
		Data:     txData.Data,
		V:        txData.V,
		R:        txData.R,
		S:        txData.S,
	}
	tx.SetFrom(signer)

	return tx, nil
}

// recoverSender recovers the sender address from a legacy transaction signature
func recoverSender(data []byte, v, r, s, chainID *big.Int) (common.Address, error) {
	// Decode the full transaction to get unsigned portion for signing hash
	var txFields []interface{}
	if err := rlp.DecodeBytes(data, &txFields); err != nil {
		return common.Address{}, err
	}

	if len(txFields) != 9 {
		return common.Address{}, errors.New("invalid legacy transaction field count")
	}

	// Calculate the signing hash (EIP-155)
	// For EIP-155: hash(nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0)
	vValue := v.Uint64()

	var signingData []byte

	if vValue >= 35 {
		// EIP-155 transaction
		// Reconstruct unsigned tx: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
		unsignedTx := []interface{}{
			txFields[0], // nonce
			txFields[1], // gasPrice
			txFields[2], // gasLimit
			txFields[3], // to
			txFields[4], // value
			txFields[5], // data
			chainID,
			uint(0),
			uint(0),
		}
		signingData, _ = rlp.EncodeToBytes(unsignedTx)
	} else {
		// Pre-EIP-155 transaction
		unsignedTx := []interface{}{
			txFields[0], // nonce
			txFields[1], // gasPrice
			txFields[2], // gasLimit
			txFields[3], // to
			txFields[4], // value
			txFields[5], // data
		}
		signingData, _ = rlp.EncodeToBytes(unsignedTx)
	}

	sigHash := crypto.Keccak256Hash(signingData)

	// Calculate recovery ID
	var recoveryID byte
	if vValue >= 35 {
		// EIP-155: v = chainId * 2 + 35 + recovery_id
		recoveryID = byte((vValue - 35 - chainID.Uint64()*2) % 2)
	} else {
		recoveryID = byte(vValue - 27)
	}

	// Build signature (r || s || recovery_id)
	sig := make([]byte, 65)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	sig[64] = recoveryID

	// Recover public key
	pubKey, err := crypto.Ecrecover(sigHash.Bytes(), sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("ecrecover failed: %w", err)
	}

	// Convert to address
	pubKeyECDSA, err := crypto.UnmarshalPubkey(pubKey)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to unmarshal pubkey: %w", err)
	}

	return crypto.PubkeyToAddress(*pubKeyECDSA), nil
}

// recoverSenderEIP2930 recovers sender from EIP-2930 transaction
func recoverSenderEIP2930(data []byte, v, r, s *big.Int) (common.Address, error) {
	// Decode transaction fields
	var txFields []interface{}
	if err := rlp.DecodeBytes(data, &txFields); err != nil {
		return common.Address{}, err
	}

	if len(txFields) != 11 {
		return common.Address{}, errors.New("invalid EIP-2930 transaction field count")
	}

	// Signing hash = keccak256(0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList]))
	unsignedFields := txFields[:8] // Everything except v, r, s
	unsignedRLP, _ := rlp.EncodeToBytes(unsignedFields)
	signingData := append([]byte{0x01}, unsignedRLP...)
	sigHash := crypto.Keccak256Hash(signingData)

	// V is just y-parity (0 or 1)
	recoveryID := byte(v.Uint64())

	sig := make([]byte, 65)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	sig[64] = recoveryID

	pubKey, err := crypto.Ecrecover(sigHash.Bytes(), sig)
	if err != nil {
		return common.Address{}, err
	}

	pubKeyECDSA, err := crypto.UnmarshalPubkey(pubKey)
	if err != nil {
		return common.Address{}, err
	}

	return crypto.PubkeyToAddress(*pubKeyECDSA), nil
}

// recoverSenderEIP1559 recovers sender from EIP-1559 transaction
func recoverSenderEIP1559(data []byte, v, r, s *big.Int) (common.Address, error) {
	// Decode transaction fields
	var txFields []interface{}
	if err := rlp.DecodeBytes(data, &txFields); err != nil {
		return common.Address{}, err
	}

	if len(txFields) != 12 {
		return common.Address{}, errors.New("invalid EIP-1559 transaction field count")
	}

	// Signing hash = keccak256(0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]))
	unsignedFields := txFields[:9] // Everything except v, r, s
	unsignedRLP, _ := rlp.EncodeToBytes(unsignedFields)
	signingData := append([]byte{0x02}, unsignedRLP...)
	sigHash := crypto.Keccak256Hash(signingData)

	// V is just y-parity (0 or 1)
	recoveryID := byte(v.Uint64())

	sig := make([]byte, 65)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	sig[64] = recoveryID

	pubKey, err := crypto.Ecrecover(sigHash.Bytes(), sig)
	if err != nil {
		return common.Address{}, err
	}

	pubKeyECDSA, err := crypto.UnmarshalPubkey(pubKey)
	if err != nil {
		return common.Address{}, err
	}

	return crypto.PubkeyToAddress(*pubKeyECDSA), nil
}

// ethCall executes a call without creating a transaction
func (s *Server) ethCall(params []json.RawMessage) (string, *RPCError) {
	if len(params) < 1 {
		return "", &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var callArgs struct {
		From     string `json:"from"`
		To       string `json:"to"`
		Data     string `json:"data"`
		Value    string `json:"value"`
		Gas      string `json:"gas"`
		GasPrice string `json:"gasPrice"`
	}
	if err := json.Unmarshal(params[0], &callArgs); err != nil {
		return "", &RPCError{Code: -32602, Message: "Invalid call args"}
	}

	// Parse addresses
	var from common.Address
	if callArgs.From != "" {
		from = common.HexToAddress(callArgs.From)
	}

	var to *common.Address
	if callArgs.To != "" {
		addr := common.HexToAddress(callArgs.To)
		to = &addr
	}

	// Parse data
	data := common.FromHex(callArgs.Data)

	// Parse value
	value := big.NewInt(0)
	if callArgs.Value != "" {
		value, _ = hexutil.DecodeBig(callArgs.Value)
	}

	// Parse gas (default to block gas limit)
	gasLimit := uint64(30000000)
	if callArgs.Gas != "" {
		gasLimit = hexToUint64(callArgs.Gas)
	}

	// Create EVM config
	evmConfig := &core.EVMConfig{
		ChainID:  s.bc.Config().ChainID,
		GasLimit: gasLimit,
	}

	// Create a copy of state for read-only execution
	stateCopy := s.bc.State().Copy()

	// Create header context
	currentBlock := s.bc.CurrentBlock()
	header := &core.BlockHeader{
		Number:    currentBlock.Number(),
		Timestamp: currentBlock.Header.Timestamp,
		GasLimit:  gasLimit,
	}

	// Create EVM instance
	evm := core.NewTurboEVM(evmConfig, stateCopy, header, common.Address{})
	evm.SetOrigin(from)
	evm.SetGasPrice(big.NewInt(1000000000))

	// Execute call
	var result []byte
	var err error

	if to == nil {
		// Contract creation (unusual for eth_call but supported)
		_, result, _, err = evm.Create(from, data, gasLimit, value)
	} else {
		// Regular call (use StaticCall for read-only)
		result, _, err = evm.StaticCall(from, *to, data, gasLimit)
	}

	if err != nil {
		// Return error but don't fail the RPC call
		log.Printf("eth_call error: %v", err)
		return "0x", nil
	}

	return hexutil.Encode(result), nil
}

// ethEstimateGas estimates gas for a transaction
func (s *Server) ethEstimateGas(params []json.RawMessage) (string, *RPCError) {
	// Return fixed gas estimate
	return "0x5208", nil // 21000
}

// ethGetLogs returns logs matching filter
func (s *Server) ethGetLogs(params []json.RawMessage) (interface{}, *RPCError) {
	// Return empty logs for now
	return []interface{}{}, nil
}

// ethFeeHistory returns fee history
func (s *Server) ethFeeHistory(params []json.RawMessage) (interface{}, *RPCError) {
	return map[string]interface{}{
		"oldestBlock":   "0x0",
		"baseFeePerGas": []string{"0x3B9ACA00"},
		"gasUsedRatio":  []float64{0.5},
		"reward":        [][]string{{"0x3B9ACA00"}},
	}, nil
}

// web3Sha3 returns keccak256 hash
func (s *Server) web3Sha3(params []json.RawMessage) (string, *RPCError) {
	if len(params) < 1 {
		return "", &RPCError{Code: -32602, Message: "Invalid params"}
	}

	var dataHex string
	json.Unmarshal(params[0], &dataHex)

	data := common.FromHex(dataHex)
	hash := common.BytesToHash(data)
	return hash.Hex(), nil
}

// hexToUint64 converts hex string to uint64
func hexToUint64(s string) uint64 {
	s = strings.TrimPrefix(s, "0x")
	n, _ := strconv.ParseUint(s, 16, 64)
	return n
}

// turboGetWithdrawalProof returns Merkle proof for a withdrawal
func (s *Server) turboGetWithdrawalProof(params []json.RawMessage) (interface{}, *RPCError) {
	if len(params) < 1 {
		return nil, &RPCError{Code: -32602, Message: "Invalid params: withdrawal index required"}
	}

	var indexHex string
	if err := json.Unmarshal(params[0], &indexHex); err != nil {
		return nil, &RPCError{Code: -32602, Message: "Invalid withdrawal index"}
	}

	index := hexToUint64(indexHex)

	proof, root, withdrawal, err := s.bc.GetWithdrawalProof(index)
	if err != nil {
		return nil, &RPCError{Code: -32000, Message: err.Error()}
	}

	if withdrawal == nil {
		return nil, &RPCError{Code: -32000, Message: "Withdrawal not found"}
	}

	// Format proof as hex strings
	proofHex := make([]string, len(proof))
	for i, p := range proof {
		proofHex[i] = p.Hex()
	}

	return map[string]interface{}{
		"withdrawalIndex": hexutil.EncodeUint64(withdrawal.WithdrawalIndex),
		"recipient":       withdrawal.Recipient.Hex(),
		"amount":          hexutil.EncodeBig(withdrawal.Amount),
		"l2BlockNumber":   hexutil.EncodeUint64(withdrawal.L2BlockNumber),
		"txHash":          withdrawal.TxHash.Hex(),
		"leafHash":        withdrawal.Hash().Hex(),
		"proof":           proofHex,
		"root":            root.Hex(),
	}, nil
}

// turboGetWithdrawalRoot returns the current withdrawal Merkle root
func (s *Server) turboGetWithdrawalRoot() (interface{}, *RPCError) {
	root := s.bc.GetWithdrawalRoot()
	pendingCount := s.bc.WithdrawalManager().PendingCount()

	return map[string]interface{}{
		"root":         root.Hex(),
		"pendingCount": pendingCount,
	}, nil
}

// turboGetPendingWithdrawals returns all pending withdrawals
func (s *Server) turboGetPendingWithdrawals() (interface{}, *RPCError) {
	withdrawals := s.bc.GetPendingWithdrawals()

	result := make([]map[string]interface{}, len(withdrawals))
	for i, w := range withdrawals {
		result[i] = map[string]interface{}{
			"withdrawalIndex": hexutil.EncodeUint64(w.WithdrawalIndex),
			"recipient":       w.Recipient.Hex(),
			"amount":          hexutil.EncodeBig(w.Amount),
			"l2BlockNumber":   hexutil.EncodeUint64(w.L2BlockNumber),
			"txHash":          w.TxHash.Hex(),
			"processed":       w.Processed,
		}
	}

	return result, nil
}

// turboGetWithdrawal returns a specific withdrawal by index
func (s *Server) turboGetWithdrawal(params []json.RawMessage) (interface{}, *RPCError) {
	if len(params) < 1 {
		return nil, &RPCError{Code: -32602, Message: "Invalid params: withdrawal index required"}
	}

	var indexHex string
	if err := json.Unmarshal(params[0], &indexHex); err != nil {
		return nil, &RPCError{Code: -32602, Message: "Invalid withdrawal index"}
	}

	index := hexToUint64(indexHex)
	withdrawal := s.bc.WithdrawalManager().GetWithdrawal(index)

	if withdrawal == nil {
		return nil, nil
	}

	return map[string]interface{}{
		"withdrawalIndex": hexutil.EncodeUint64(withdrawal.WithdrawalIndex),
		"recipient":       withdrawal.Recipient.Hex(),
		"amount":          hexutil.EncodeBig(withdrawal.Amount),
		"l2BlockNumber":   hexutil.EncodeUint64(withdrawal.L2BlockNumber),
		"txHash":          withdrawal.TxHash.Hex(),
		"processed":       withdrawal.Processed,
		"leafHash":        withdrawal.Hash().Hex(),
	}, nil
}
