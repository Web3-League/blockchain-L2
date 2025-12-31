# NanoPy Turbo L2

Layer 2 blockchain for NanoPy, written in Go.

## Quick Start

```bash
# Build
go build -o turbo ./cmd/turbo

# Run (testnet)
./turbo --network testnet --l1-rpc http://51.68.125.99:8546

# Run (mainnet)
./turbo --network mainnet --l1-rpc http://51.68.125.99:8545
```

## Networks

| Network | Chain ID | RPC | Port |
|---------|----------|-----|------|
| Turbo Testnet | 777702 | http://51.68.125.99:8548 | 8548 |
| Turbo Mainnet | 77702 | http://51.68.125.99:8547 | 8547 |

## Features

- EVM compatible
- ~10s block time
- Native bridge to L1
- JSON-RPC API

## License

MIT
