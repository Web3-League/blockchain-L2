package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/nanopy/nanopy-turbo/core"
	"github.com/nanopy/nanopy-turbo/rpc"
	"github.com/nanopy/nanopy-turbo/sequencer"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "turbo",
		Short: "NanoPy Turbo L2 Node",
		Long: `NanoPy Turbo - High Performance L2 on NanoPy

Chain IDs:
  - Mainnet L2: 77702
  - Testnet L2: 777702

Example:
  turbo --sequencer --rpc-addr :8547`,
	}

	// Flags
	var (
		dataDir      string
		rpcAddr      string
		isSequencer  bool
		sequencerKey string
		testnet      bool
		l1RPC        string
		l1Bridge     string
		blockTime    int
		genesisFile  string
	)

	rootCmd.Flags().StringVar(&dataDir, "datadir", "./turbo-data", "Data directory")
	rootCmd.Flags().StringVar(&rpcAddr, "rpc-addr", ":8547", "RPC server address")
	rootCmd.Flags().BoolVar(&isSequencer, "sequencer", false, "Run as sequencer")
	rootCmd.Flags().StringVar(&sequencerKey, "sequencer-key", "", "Sequencer private key (hex)")
	rootCmd.Flags().BoolVar(&testnet, "testnet", false, "Use testnet configuration")
	rootCmd.Flags().StringVar(&l1RPC, "l1-rpc", "", "L1 RPC URL (for state root submission)")
	rootCmd.Flags().StringVar(&l1Bridge, "l1-bridge", "", "L1 Bridge contract address")
	rootCmd.Flags().IntVar(&blockTime, "block-time", 2, "Block time in seconds")
	rootCmd.Flags().StringVar(&genesisFile, "genesis", "", "Path to genesis.json file")

	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		printBanner()

		// Select config
		var config *core.ChainConfig
		if testnet {
			config = core.TestnetTurboConfig()
			log.Println("Network: NanoPy Turbo Testnet (chain_id: 777702)")
		} else {
			config = core.DefaultTurboConfig()
			log.Println("Network: NanoPy Turbo Mainnet (chain_id: 77702)")
		}

		if l1RPC != "" {
			config.L1RPC = l1RPC
		}

		// Load genesis if provided
		var genesis *core.Genesis
		if genesisFile != "" {
			var err error
			genesis, err = core.LoadGenesis(genesisFile)
			if err != nil {
				log.Fatalf("Failed to load genesis: %v", err)
			}
			log.Printf("Loaded genesis from: %s", genesisFile)
			log.Printf("Genesis allocations: %d accounts", len(genesis.Alloc))
		}

		// Create blockchain
		bc, err := core.NewBlockchainWithGenesis(config, dataDir, genesis)
		if err != nil {
			log.Fatalf("Failed to create blockchain: %v", err)
		}
		defer bc.Close()

		log.Printf("Data directory: %s", dataDir)
		log.Printf("Current block: #%d", bc.CurrentBlock().Number().Uint64())

		// Start RPC server
		rpcServer := rpc.NewServer(bc, rpcAddr)
		go func() {
			if err := rpcServer.Start(); err != nil {
				log.Fatalf("RPC server failed: %v", err)
			}
		}()
		log.Printf("RPC server: http://localhost%s", rpcAddr)

		// Start sequencer if enabled
		if isSequencer {
			var coinbase common.Address
			if sequencerKey != "" {
				key, err := crypto.HexToECDSA(sequencerKey)
				if err != nil {
					log.Fatalf("Invalid sequencer key: %v", err)
				}
				coinbase = crypto.PubkeyToAddress(key.PublicKey)
			} else {
				// Generate random key for testing
				key, _ := crypto.GenerateKey()
				coinbase = crypto.PubkeyToAddress(key.PublicKey)
				log.Printf("Generated sequencer address: %s", coinbase.Hex())
				log.Println("WARNING: Using random key. Set --sequencer-key for production!")
			}

			seqConfig := &sequencer.Config{
				Coinbase:  coinbase,
				BlockTime: time.Duration(blockTime) * time.Second,
				L1RPC:     config.L1RPC,
				L1Bridge:  common.HexToAddress(l1Bridge),
			}

			if l1Bridge != "" {
				log.Printf("L1 Bridge: %s", l1Bridge)
			}

			seq := sequencer.NewSequencer(bc, seqConfig)
			seq.OnBlock(func(block *core.Block) {
				log.Printf("New block #%d (hash: %s)",
					block.Number().Uint64(),
					block.Hash().Hex()[:16]+"...",
				)
			})
			seq.Start()
			defer seq.Stop()
		}

		// Wait for shutdown
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		log.Println("Shutting down...")
	}

	// Version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("NanoPy Turbo v%s\n", version)
		},
	}
	rootCmd.AddCommand(versionCmd)

	// Genesis command
	genesisCmd := &cobra.Command{
		Use:   "genesis",
		Short: "Show genesis configuration",
		Run: func(cmd *cobra.Command, args []string) {
			genesis := core.DefaultGenesis()
			fmt.Println("NanoPy Turbo Genesis Configuration")
			fmt.Println("===================================")
			fmt.Printf("Chain ID:   %d\n", genesis.Config.ChainID)
			fmt.Printf("L1 Chain:   %d\n", genesis.Config.L1ChainID)
			fmt.Printf("L1 RPC:     %s\n", genesis.Config.L1RPC)
			fmt.Printf("Block Time: %ds\n", genesis.Config.BlockTime)
			fmt.Printf("Gas Limit:  %d\n", genesis.GasLimit)
			fmt.Println("\nInitial Allocations:")
			for addr, alloc := range genesis.Alloc {
				fmt.Printf("  %s: %s\n", addr, alloc.Balance)
			}
		},
	}
	rootCmd.AddCommand(genesisCmd)

	// Account command
	accountCmd := &cobra.Command{
		Use:   "account",
		Short: "Generate new account",
		Run: func(cmd *cobra.Command, args []string) {
			key, err := crypto.GenerateKey()
			if err != nil {
				log.Fatalf("Failed to generate key: %v", err)
			}

			addr := crypto.PubkeyToAddress(key.PublicKey)
			privKey := fmt.Sprintf("%x", crypto.FromECDSA(key))

			fmt.Println("New Account Generated")
			fmt.Println("=====================")
			fmt.Printf("Address:     %s\n", addr.Hex())
			fmt.Printf("Private Key: %s\n", privKey)
			fmt.Println("\nWARNING: Save your private key securely!")
		},
	}
	rootCmd.AddCommand(accountCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func printBanner() {
	banner := `
 _   _                   ____        _____         _
| \ | | __ _ _ __   ___ |  _ \ _   _|_   _|   _ _ | |__ ___
|  \| |/ _' | '_ \ / _ \| |_) | | | | | || | | || '__| / _ \
| |\  | (_| | | | | (_) |  __/| |_| | | || |_| || |   | (_) |
|_| \_|\__,_|_| |_|\___/|_|    \__, | |_| \__,_||_|    \___/
                               |___/                  v%s
    L2 on NanoPy - High Performance Layer 2
`
	fmt.Printf(banner, version)
	fmt.Println()
}
