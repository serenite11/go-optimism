package miner

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	"github.com/serenite11/op-geth/common"
	"github.com/serenite11/op-geth/consensus/clique"
	"github.com/serenite11/op-geth/core"
	"github.com/serenite11/op-geth/core/rawdb"
	"github.com/serenite11/op-geth/core/state"
	"github.com/serenite11/op-geth/core/txpool"
	"github.com/serenite11/op-geth/core/txpool/legacypool"
	"github.com/serenite11/op-geth/core/types"
	"github.com/serenite11/op-geth/core/types/interoptypes"
	"github.com/serenite11/op-geth/core/vm"
	"github.com/serenite11/op-geth/crypto"
	"github.com/serenite11/op-geth/event"
	"github.com/serenite11/op-geth/params"
	"github.com/serenite11/op-geth/triedb"
	"github.com/stretchr/testify/require"
)

func createInteropMiner(t *testing.T, supervisorInFailsafe bool, queryFailsafeCb func()) (*Miner, *ecdsa.PrivateKey, common.Address) {
	// Create Ethash config with interop enabled
	config := Config{
		PendingFeeRecipient:                   common.HexToAddress("123456789"),
		RollupTransactionConditionalRateLimit: params.TransactionConditionalMaxCost,
	}

	// Create chainConfig with interop enabled
	chainDB := rawdb.NewMemoryDatabase()
	triedb := triedb.NewDatabase(chainDB, nil)

	// Create test keys that will have funds in genesis
	testBankKey, _ := crypto.GenerateKey()
	testBankAddress := crypto.PubkeyToAddress(testBankKey.PublicKey)

	genesis := minerTestGenesisBlock(15, 11_500_000, testBankAddress)

	// Enable interop by setting InteropTime to 0
	genesis.Config.InteropTime = new(uint64)
	*genesis.Config.InteropTime = 0

	chainConfig, _, _, err := core.SetupGenesisBlock(chainDB, triedb, genesis)
	if err != nil {
		t.Fatalf("can't create new chain config: %v", err)
	}

	// Create consensus engine
	engine := clique.New(chainConfig.Clique, chainDB)

	// Create Ethereum backend
	bc, err := core.NewBlockChain(chainDB, nil, genesis, nil, engine, vm.Config{}, nil)
	if err != nil {
		t.Fatalf("can't create new chain %v", err)
	}

	statedb, _ := state.New(bc.Genesis().Root(), bc.StateCache())
	blockchain := &testBlockChain{bc.Genesis().Root(), chainConfig, statedb, 10000000, new(event.Feed)}

	pool := legacypool.New(legacypool.DefaultConfig, blockchain)
	txpool, _ := txpool.New(legacypool.DefaultConfig.PriceLimit, blockchain, []txpool.SubPool{pool}, nil)

	// Create mock backend with interop support
	backend := NewMockBackend(bc, txpool, supervisorInFailsafe, queryFailsafeCb)

	miner := New(backend, config, engine)
	return miner, testBankKey, testBankAddress
}

func createInteropTransaction(t *testing.T, miner *Miner, testBankKey *ecdsa.PrivateKey, testUserAddress common.Address) *types.Transaction {
	// Create an interop transaction with executing messages (access list)
	signer := types.LatestSigner(miner.chainConfig)

	// Create a transaction with access list pointing to CrossL2Inbox (interop address)
	accessList := types.AccessList{
		{
			Address: params.InteropCrossL2InboxAddress,
			StorageKeys: []common.Hash{
				common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			},
		},
	}

	// Calculate gas needed: base gas + access list cost
	// Access list cost: 2400 for address + 1900 per storage key
	gasNeeded := params.TxGas + 2400 + 1900

	tx := types.MustSignNewTx(testBankKey, signer, &types.DynamicFeeTx{
		ChainID:    miner.chainConfig.ChainID,
		Nonce:      0,
		To:         &testUserAddress,
		Value:      big.NewInt(1000),
		Gas:        gasNeeded,
		GasFeeCap:  big.NewInt(params.InitialBaseFee * 2),
		GasTipCap:  big.NewInt(params.InitialBaseFee),
		AccessList: accessList,
	})

	// Verify the transaction has executing messages
	execMsgs := interoptypes.TxToInteropAccessList(tx)
	if len(execMsgs) == 0 {
		t.Fatalf("transaction should have executing messages")
	}

	return tx
}

// testInteropTransaction runs a complete interop transaction test
func testInteropTransaction(t *testing.T, failsafeEnabled bool, expectIncluded bool, expectRejected bool) {
	miner, testBankKey, testUserAddress := createInteropMiner(t, failsafeEnabled, nil)
	tx := createInteropTransaction(t, miner, testBankKey, testUserAddress)

	// Add the transaction to the pool
	err := miner.txpool.Add(types.Transactions{tx}, false)
	if len(err) > 0 && err[0] != nil {
		t.Fatalf("Failed to add interop transaction to pool: %v", err[0])
	}

	if !miner.txpool.Has(tx.Hash()) {
		t.Fatalf("interop transaction is not in the mempool")
	}

	// Request block generation with RPC context (required for interop check)
	timestamp := uint64(time.Now().Unix())
	r := miner.generateWork(&generateParams{
		parentHash: miner.chain.CurrentBlock().Hash(),
		timestamp:  timestamp,
		random:     common.HexToHash("0xcafebabe"),
		noTxs:      false,
		forceTime:  true,
		rpcCtx:     context.Background(), // Enable interop checks
	}, false)

	// Check transaction inclusion in block
	if expectIncluded {
		if len(r.block.Transactions()) != 1 {
			t.Fatalf("block should contain 1 transaction, got %d transactions", len(r.block.Transactions()))
		}
	} else {
		if len(r.block.Transactions()) != 0 {
			t.Fatalf("block should be empty, got %d transactions", len(r.block.Transactions()))
		}
	}

	// Check transaction rejection status
	if expectRejected {
		if !tx.Rejected() {
			t.Fatalf("interop transaction should be marked as rejected")
		}
		// Rejected transaction should be evicted from the txpool
		miner.txpool.Sync()
		if miner.txpool.Has(tx.Hash()) {
			t.Fatalf("rejected interop transaction should be evicted from the mempool")
		}
	} else {
		if tx.Rejected() {
			t.Fatalf("interop transaction should not be marked as rejected")
		}
		// Transaction should still be in the txpool
		if !miner.txpool.Has(tx.Hash()) {
			t.Fatalf("successful interop transaction should still be in the mempool")
		}
	}
}

func TestInteropTxRejectedWithFailsafe(t *testing.T) {
	t.Run("failsafe enabled", func(t *testing.T) {
		testInteropTransaction(t, true, false, true) // not included, rejected
	})
	t.Run("failsafe disabled", func(t *testing.T) {
		testInteropTransaction(t, false, true, false) // included, not rejected
	})
}

func TestFailsafeDetection(t *testing.T) {
	supervisorRPCCalls := 0
	cb := func() {
		supervisorRPCCalls++
	}
	// Create a miner, but do no work
	createInteropMiner(t, true, cb)
	require.Eventually(t, func() bool {
		return supervisorRPCCalls > 0
	}, 10*time.Second, 100*time.Millisecond, "supervisor RPC calls should be made")
}
