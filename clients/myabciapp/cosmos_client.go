package myabciapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

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
	"github.com/gorilla/websocket"
	"github.com/sagaxyz/tm-load-test/pkg/loadtest"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"` // must be map[string]interface{} or []interface{}
}

func ImportUnecryptedHexKey(privKeyHex string) cryptotypes.PrivKey {
	k := ethsecp256k1.PrivKey{Key: common.FromHex(privKeyHex)}
	return &k
}

func GetAccountNums(addr string) (uint64, uint64, error) {
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

func NewMsg(from, to types.AccAddress, amount int64) (*banktypes.MsgSend, error) {
	msg := banktypes.NewMsgSend(from, to, types.NewCoins(types.NewInt64Coin("asaga", amount)))
	err := msg.ValidateBasic()
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func AddSign(signerData xauthsigning.SignerData, txBuilder client.TxBuilder, priv cryptotypes.PrivKey, txConfig client.TxConfig, accSeq uint64) (signing.SignatureV2, error) {
	var sigV2 signing.SignatureV2

	// Generate the bytes to be signed.
	signBytes, err := txConfig.SignModeHandler().GetSignBytes(txConfig.SignModeHandler().DefaultMode(), signerData, txBuilder.GetTx())
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
		SignMode:  txConfig.SignModeHandler().DefaultMode(),
		Signature: signature,
	}

	sigV2 = signing.SignatureV2{
		PubKey:   priv.PubKey(),
		Data:     &sigData,
		Sequence: accSeq,
	}

	return sigV2, nil
}

func DoSign(txConfig client.TxConfig, txBuilder client.TxBuilder, priv cryptotypes.PrivKey, num, seq uint64) error {
	sigV2 := signing.SignatureV2{
		PubKey: priv.PubKey(),
		Data: &signing.SingleSignatureData{
			SignMode:  txConfig.SignModeHandler().DefaultMode(),
			Signature: nil,
		},
		Sequence: uint64(seq),
	}

	err := txBuilder.SetSignatures(sigV2)
	if err != nil {
		return err
	}

	// Second round: all signer infos are set, so each signer can sign.
	signerData := xauthsigning.SignerData{
		ChainID:       "sevm_100-909",
		AccountNumber: num,
		Sequence:      uint64(seq),
	}
	sigV2, err = AddSign(signerData, txBuilder, priv, txConfig, seq)
	if err != nil {
		return err
	}

	err = txBuilder.SetSignatures(sigV2)
	if err != nil {
		return err
	}

	return nil
}

func SendRawTx(tx []byte, remoteAddr string) error {
	txBase64 := base64.StdEncoding.EncodeToString(tx)
	paramsJSON, err := json.Marshal(map[string]interface{}{"tx": txBase64})
	if err != nil {
		return err
	}

	u, err := url.Parse(remoteAddr)
	if err != nil {
		return err
	}

	conn, resp, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("failed to connect to remote WebSockets endpoint %s: %s (status code %d)", remoteAddr, resp.Status, resp.StatusCode)
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return conn.WriteJSON(RPCRequest{
		JSONRPC: "2.0",
		ID:      -1,
		Method:  "broadcast_tx_commit",
		Params:  json.RawMessage(paramsJSON),
	})
}

// CosmosClientFactory creates instances of CosmosClient
type CosmosClientFactory struct {
	txConfig            client.TxConfig
	conn                *grpc.ClientConn
	mainPrivKeyHex      string
	mainPrivKeyCosmos   cryptotypes.PrivKey
	mainAddressBech32   types.AccAddress
	mainAccountNumber   uint64
	mainAccountSequence uint64
}

// CosmosClientFactory implements loadtest.ClientFactory
var _ loadtest.ClientFactory = (*CosmosClientFactory)(nil)

func NewCosmosClientFactory(txConfig client.TxConfig, conn *grpc.ClientConn) *CosmosClientFactory {
	// this key should have non-zero balance
	keyEnvVar := "MAIN_PRIV_KEY_HEX"
	mainPrivKeyHex := os.Getenv(keyEnvVar)
	if mainPrivKeyHex == "" {
		logrus.Errorf("environment variable %s is not set", keyEnvVar)
		return nil
	}
	mainPrivKeyCosmos := ImportUnecryptedHexKey(mainPrivKeyHex)
	mainAddressBech32, err := bech32.ConvertAndEncode("saga", mainPrivKeyCosmos.PubKey().Address().Bytes())
	if err != nil {
		logrus.Errorf("%v", err)
		return nil
	}
	logrus.Infof("New main account address [%s, %s]", mainAddressBech32, mainPrivKeyCosmos.PubKey().Address().String())

	num, seq, err := GetAccountNums(mainAddressBech32)
	if err != nil {
		logrus.Errorf("%v", err)
		return nil
	}
	logrus.Infof("acc num: %d, seq: %d", num, seq)

	addrFrom, err := types.AccAddressFromBech32(mainAddressBech32)
	if err != nil {
		logrus.Errorf("%v", err)
		return nil
	}
	return &CosmosClientFactory{
		txConfig:            txConfig,
		conn:                conn,
		mainPrivKeyHex:      mainPrivKeyHex,
		mainPrivKeyCosmos:   mainPrivKeyCosmos,
		mainAddressBech32:   addrFrom,
		mainAccountNumber:   num,
		mainAccountSequence: seq,
	}
}

// CosmosClient is responsible for generating transactions. Only one client
// will be created per connection to the remote Tendermint RPC endpoint, and
// each client will be responsible for maintaining its own state in a
// thread-safe manner.
type CosmosClient struct {
	txConfig      client.TxConfig
	conn          *grpc.ClientConn
	privKeyCosmos cryptotypes.PrivKey
	addressBech32 types.AccAddress
	num           uint64
	seq           uint64
}

// CosmosClient implements loadtest.Client
var _ loadtest.Client = (*CosmosClient)(nil)

func (f *CosmosClientFactory) ValidateConfig(cfg loadtest.Config) error {
	// Do any checks here that you need to ensure that the load test
	// configuration is compatible with your client.
	return nil
}

func (f *CosmosClientFactory) NewClient(cfg loadtest.Config) (loadtest.Client, error) {
	// create new account
	newKey, err := ethsecp256k1.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	newAddressBech32, err := bech32.ConvertAndEncode("saga", newKey.PubKey().Address().Bytes())
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	logrus.Infof("New client account address [%s, %s]", newAddressBech32, newKey.PubKey().Address().String())

	addrNew, err := types.AccAddressFromBech32(newAddressBech32)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	// generate tx and send funds to a new account
	txBuilder := f.txConfig.NewTxBuilder()

	msg, err := NewMsg(f.mainAddressBech32, addrNew, 1000000000)
	if err != nil {
		return nil, err
	}

	err = txBuilder.SetMsgs(msg)
	if err != nil {
		return nil, fmt.Errorf("SetMsgs failed: %v", err)
	}

	txBuilder.SetMemo("funding")
	txBuilder.SetGasLimit(200000)
	txBuilder.SetFeeAmount(types.NewCoins(types.NewInt64Coin("asaga", 100)))

	err = DoSign(f.txConfig, txBuilder, f.mainPrivKeyCosmos, f.mainAccountNumber, f.mainAccountSequence)
	if err != nil {
		return nil, err
	}
	f.mainAccountSequence++

	tx := txBuilder.GetTx()
	txBytes, err := f.txConfig.TxEncoder()(tx)
	if err != nil {
		return nil, err
	}

	// send tx
	err = SendRawTx(txBytes, cfg.Endpoints[0])
	if err != nil {
		return nil, fmt.Errorf("Tx broadcast failed: %v", err)
	}

	time.Sleep(5 * time.Second)

	num, seq, err := GetAccountNums(newAddressBech32)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	logrus.Infof("acc num: %d, seq: %d", num, seq)

	return &CosmosClient{
		txConfig:      f.txConfig,
		conn:          f.conn,
		privKeyCosmos: newKey,
		addressBech32: addrNew,
		num:           num,
		seq:           seq,
	}, nil
}

// GenerateTx must return the raw bytes that make up the transaction for your
// ABCI app. The conversion to base64 will automatically be handled by the
// loadtest package, so don't worry about that. Only return an error here if you
// want to completely fail the entire load test operation.
func (c *CosmosClient) GenerateTx() ([]byte, error) {
	newKey, err := ethsecp256k1.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	newAddressBech32, err := bech32.ConvertAndEncode("saga", newKey.PubKey().Address().Bytes())
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	toAddresses := []string{newAddressBech32}

	var msgs []types.Msg
	txBuilder := c.txConfig.NewTxBuilder()
	for _, to := range toAddresses {
		addrTo, err := types.AccAddressFromBech32(to)
		if err != nil {
			return nil, err
		}

		msg, err := NewMsg(c.addressBech32, addrTo, 12)
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

	err = DoSign(c.txConfig, txBuilder, c.privKeyCosmos, c.num, c.seq)
	if err != nil {
		return nil, err
	}
	c.seq++

	tx := txBuilder.GetTx()
	err = tx.ValidateBasic()
	if err != nil {
		return nil, err
	}

	txBytes, err := c.txConfig.TxEncoder()(tx)
	if err != nil {
		return nil, err
	}

	return txBytes, err
}
