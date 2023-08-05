package myabciapp

import (
	"context"
	"fmt"
	"math"
	"os"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	grpctypes "github.com/cosmos/cosmos-sdk/types/grpc"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	xauthsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/evmos/ethermint/crypto/ethsecp256k1"
	etherminttypes "github.com/evmos/ethermint/types"
	"github.com/informalsystems/tm-load-test/pkg/loadtest"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// CosmosClientFactory creates instances of CosmosClient
type CosmosClientFactory struct {
	txConfig client.TxConfig
	conn     *grpc.ClientConn
}

// CosmosClientFactory implements loadtest.ClientFactory
var _ loadtest.ClientFactory = (*CosmosClientFactory)(nil)

func NewCosmosClientFactory(txConfig client.TxConfig, conn *grpc.ClientConn) *CosmosClientFactory {
	return &CosmosClientFactory{
		txConfig: txConfig,
		conn:     conn,
	}
}

// CosmosClient is responsible for generating transactions. Only one client
// will be created per connection to the remote Tendermint RPC endpoint, and
// each client will be responsible for maintaining its own state in a
// thread-safe manner.
type CosmosClient struct {
	txConfig client.TxConfig
	conn     *grpc.ClientConn
	seq      uint64
	num      uint64
}

// CosmosClient implements loadtest.Client
var _ loadtest.Client = (*CosmosClient)(nil)

func (f *CosmosClientFactory) ValidateConfig(cfg loadtest.Config) error {
	// Do any checks here that you need to ensure that the load test
	// configuration is compatible with your client.
	return nil
}

func (f *CosmosClientFactory) NewClient(cfg loadtest.Config) (loadtest.Client, error) {
	return &CosmosClient{
		txConfig: f.txConfig,
		conn:     f.conn,
		seq:      math.MaxUint64,
		num:      math.MaxUint64,
	}, nil
}

func (c *CosmosClient) GetAccountNums(addr string) (uint64, uint64, error) {
	if c.seq != math.MaxUint64 {
		return c.num, c.seq, nil
	}

	var header metadata.MD

	con, err := grpc.Dial("localhost:9090", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return 0, 0, err
	}
	defer con.Close()

	queryClient := authtypes.NewQueryClient(con)

	res, err := queryClient.Account(context.Background(), &authtypes.QueryAccountRequest{Address: addr}, grpc.Header(&header))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get account data: %v", err)
	}

	blockHeight := header.Get(grpctypes.GRPCBlockHeightHeader)
	if l := len(blockHeight); l != 1 {
		return 0, 0, fmt.Errorf("unexpected '%s' header length; got %d, expected: %d", grpctypes.GRPCBlockHeightHeader, l, 1)
	}

	cdc := codec.NewProtoCodec(codectypes.NewInterfaceRegistry())
	cdc.InterfaceRegistry().RegisterImplementations((*authtypes.AccountI)(nil), &etherminttypes.EthAccount{})
	cdc.InterfaceRegistry().RegisterImplementations((*authtypes.AccountI)(nil), &authtypes.BaseAccount{})
	cdc.InterfaceRegistry().RegisterImplementations((*cryptotypes.PubKey)(nil), &ethsecp256k1.PubKey{})

	var acc authtypes.AccountI
	if err := cdc.UnpackAny(res.Account, &acc); err != nil {
		return 0, 0, fmt.Errorf("unpack failed: %v", err)
	}

	return acc.GetAccountNumber(), acc.GetSequence(), nil
}

func (c *CosmosClient) AddSign(signMode signing.SignMode, signerData xauthsigning.SignerData, txBuilder client.TxBuilder, priv cryptotypes.PrivKey, txConfig client.TxConfig, accSeq uint64) (signing.SignatureV2, error) {
	var sigV2 signing.SignatureV2

	// Generate the bytes to be signed.
	signBytes, err := txConfig.SignModeHandler().GetSignBytes(signMode, signerData, txBuilder.GetTx())
	if err != nil {
		return sigV2, err
	}

	// Sign those bytes
	signature, err := priv.Sign(signBytes)
	if err != nil {
		return sigV2, err
	}

	// Construct the SignatureV2 struct
	sigData := signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: signature,
	}

	sigV2 = signing.SignatureV2{
		PubKey:   priv.PubKey(),
		Data:     &sigData,
		Sequence: accSeq,
	}

	return sigV2, nil
}

func (c *CosmosClient) DoSign(txBuilder client.TxBuilder, priv cryptotypes.PrivKey) error {
	sigV2 := signing.SignatureV2{
		PubKey: priv.PubKey(),
		Data: &signing.SingleSignatureData{
			SignMode:  c.txConfig.SignModeHandler().DefaultMode(),
			Signature: nil,
		},
		Sequence: uint64(c.seq),
	}

	err := txBuilder.SetSignatures(sigV2)
	if err != nil {
		return err
	}

	// Second round: all signer infos are set, so each signer can sign.
	signerData := xauthsigning.SignerData{
		ChainID:       "sevm_100-505",
		AccountNumber: c.num,
		Sequence:      uint64(c.seq),
	}
	sigV2, err = c.AddSign(c.txConfig.SignModeHandler().DefaultMode(), signerData, txBuilder, priv, c.txConfig, uint64(c.seq))
	if err != nil {
		return err
	}

	err = txBuilder.SetSignatures(sigV2)
	if err != nil {
		return err
	}

	c.seq++

	return nil
}

func (c *CosmosClient) ImportUnecryptedHexKey(privKeyHex string) cryptotypes.PrivKey {
	k := ethsecp256k1.PrivKey{Key: common.FromHex(privKeyHex)}
	return &k
}

func (c *CosmosClient) NewMsg(from, to types.AccAddress) (*banktypes.MsgSend, error) {
	msg := banktypes.NewMsgSend(from, to, types.NewCoins(types.NewInt64Coin("asaga", 12)))
	err := msg.ValidateBasic()
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// GenerateTx must return the raw bytes that make up the transaction for your
// ABCI app. The conversion to base64 will automatically be handled by the
// loadtest package, so don't worry about that. Only return an error here if you
// want to completely fail the entire load test operation.
func (c *CosmosClient) GenerateTx() ([]byte, error) {
	// 0x0AA1012D993e497682B7e451AAF781F2C86945f7 saga1p2ssztve8eyhdq4hu3g64aup7tyxj30hfk2lwj
	// this key should have non-zero balance
	keyEnvVar := "MAIN_PRIV_KEY_HEX"
	mainPrivKeyHex := os.Getenv(keyEnvVar)
	if mainPrivKeyHex == "" {
		return nil, fmt.Errorf("environment variable %s is not set", keyEnvVar)
	}
	mainPrivKeyCosmos := c.ImportUnecryptedHexKey(mainPrivKeyHex)
	mainAddressBech32, err := bech32.ConvertAndEncode("saga", mainPrivKeyCosmos.PubKey().Address().Bytes())
	if err != nil {
		return nil, err
	}
	logrus.Infof("%s", mainAddressBech32)
	logrus.Infof("%s", mainPrivKeyCosmos.PubKey().Address().String())

	num, seq, err := c.GetAccountNums(mainAddressBech32)
	if err != nil {
		return nil, err
	}
	c.num, c.seq = num, seq
	logrus.Infof("acc num: %d, seq: %d", num, seq)

	addrFrom, err := types.AccAddressFromBech32(mainAddressBech32)
	if err != nil {
		return nil, err
	}
	toAddresses := []string{"saga1kdayzsaumwnpzyp4nkhf5whx6668mxpd4cg5zy", "saga1hz8vlv6gcvz5kwd945zamm7jg88xlt3hylga8f"}

	var msgs []types.Msg
	txBuilder := c.txConfig.NewTxBuilder()
	for _, to := range toAddresses {
		addrTo, err := types.AccAddressFromBech32(to)
		if err != nil {
			return nil, err
		}

		msg, err := c.NewMsg(addrFrom, addrTo)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
	}

	err = txBuilder.SetMsgs(msgs...)
	if err != nil {
		return nil, fmt.Errorf("SetMsgs failed: %v", err)
	}

	txBuilder.SetMemo("testing")
	txBuilder.SetGasLimit(200000)
	txBuilder.SetFeeAmount(types.NewCoins(types.NewInt64Coin("asaga", 100)))

	err = c.DoSign(txBuilder, mainPrivKeyCosmos)
	if err != nil {
		return nil, err
	}

	tx := txBuilder.GetTx()
	txBytes, err := c.txConfig.TxEncoder()(tx)
	if err != nil {
		return nil, err
	}

	err = tx.ValidateBasic()
	if err != nil {
		return nil, err
	}

	return txBytes, err
}
