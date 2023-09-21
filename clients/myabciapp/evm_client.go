package myabciapp

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sagaxyz/tm-load-test/pkg/loadtest"
	"github.com/sirupsen/logrus"
)

// EvmClientFactory creates instances of EvmClient
type EvmClientFactory struct {
	mainPrivKey *ecdsa.PrivateKey
	mainAddress common.Address
}

// EvmClientFactory implements loadtest.ClientFactory
var _ loadtest.ClientFactory = (*EvmClientFactory)(nil)

func NewEvmClientFactory() *EvmClientFactory {
	// this key should have non-zero balance
	keyEnvVar := "MAIN_PRIV_KEY_HEX"
	mainPrivKeyHex := os.Getenv(keyEnvVar)
	if mainPrivKeyHex == "" {
		logrus.Errorf("environment variable %s is not set", keyEnvVar)
		return nil
	}

	privateKey, err := crypto.HexToECDSA(mainPrivKeyHex)
	if err != nil {
		logrus.Errorf("unable to get ECDSA private key: %v", err)
		return nil
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		logrus.Error("error casting public key to ECDSA")
		return nil
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	return &EvmClientFactory{
		mainPrivKey: privateKey,
		mainAddress: address,
	}
}

// EvmClient is responsible for generating transactions. Only one client
// will be created per connection to the remote Tendermint RPC endpoint, and
// each client will be responsible for maintaining its own state in a
// thread-safe manner.
type EvmClient struct {
	privateKey *ecdsa.PrivateKey
	address    common.Address
	nonce      uint64
	gasPrice   *big.Int
	networkId  *big.Int
}

// EvmClient implements loadtest.Client
var _ loadtest.Client = (*EvmClient)(nil)

func (f *EvmClientFactory) ValidateConfig(cfg loadtest.Config) error {
	// Do any checks here that you need to ensure that the load test
	// configuration is compatible with your client.
	return nil
}

func (f *EvmClientFactory) NewClient(cfg loadtest.Config) (loadtest.Client, error) {
	// create new account
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("unable to generate ECDSA private key: %v", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}
	addrNew := crypto.PubkeyToAddress(*publicKeyECDSA)
	logrus.Infof("generated new client address: %s", addrNew.Hex())

	ethUrl, err := url.Parse(cfg.Endpoints[0])
	if err != nil {
		return nil, fmt.Errorf("unable to parse url: %v", err)
	}
	ethUrl.Scheme = "http"
	ethUrl.Host = strings.Replace(ethUrl.Host, ethUrl.Port(), "8545", 1)

	client, err := ethclient.Dial(ethUrl.String())
	if err != nil {
		return nil, fmt.Errorf("unable to dial: %v", err)
	}

	nonce, err := client.PendingNonceAt(context.Background(), f.mainAddress)
	if err != nil {
		return nil, fmt.Errorf("unable to get nonce: %v", err)
	}

	// generate tx and send funds to a new account
	value := big.NewInt(1000000000000000000) // in wei (1 eth)
	gasLimit := uint64(21000)                // in units

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, fmt.Errorf("unable to calculate gas price: %v", err)
	}

	tx := types.NewTransaction(nonce, addrNew, value, gasLimit, gasPrice, nil)

	// send tx
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("unable to get network id: %v", err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), f.mainPrivKey)
	if err != nil {
		return nil, fmt.Errorf("cannot sign tx: %v", err)
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return nil, fmt.Errorf("unable to send transaction: %v", err)
	}

	time.Sleep(5 * time.Second)

	newAccNonce, err := client.PendingNonceAt(context.Background(), addrNew)
	if err != nil {
		return nil, fmt.Errorf("unable to get nonce for new account: %v", err)
	}
	logrus.Infof("new acc nonce: %d, gas price: %d", newAccNonce, gasPrice)

	client.Close()

	return &EvmClient{
		privateKey: privateKey,
		address:    addrNew,
		nonce:      newAccNonce,
		gasPrice:   gasPrice,
		networkId:  chainID,
	}, nil
}

// GenerateTx must return the raw bytes that make up the transaction for your
// ABCI app. The conversion to base64 will automatically be handled by the
// loadtest package, so don't worry about that. Only return an error here if you
// want to completely fail the entire load test operation.
func (c *EvmClient) GenerateTx() ([]byte, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("unable to generate ECDSA private key: %v", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error casting public key to ECDSA")
	}
	addrNew := crypto.PubkeyToAddress(*publicKeyECDSA)
	logrus.Debugf("generated new random address: %s", addrNew.Hex())

	// generate tx and send funds to a new account
	value := big.NewInt(100)  // in wei
	gasLimit := uint64(21000) // in units

	tx := types.NewTransaction(c.nonce, addrNew, value, gasLimit, c.gasPrice, nil)

	// send tx
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(c.networkId), c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot sign tx: %v", err)
	}

	bytesData, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("unable to marshal tx: %v", err)
	}

	c.nonce++

	return bytesData, nil
}
