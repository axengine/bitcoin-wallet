package main

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/cosmos/go-bip39"
)

// GenerateMnemonic 生成新的助记词
func GenerateMnemonic(entropyBits int) (string, error) {
	// 熵长度（位）必须是32的倍数，且128-256之间
	if entropyBits%32 != 0 || entropyBits < 128 || entropyBits > 256 {
		return "", fmt.Errorf("invalid entropy bits: %d", entropyBits)
	}

	entropy, err := bip39.NewEntropy(entropyBits)
	if err != nil {
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	return mnemonic, nil
}

// BIP39Wallet BIP39钱包
type BIP39Wallet struct {
	Mnemonic string
	Seed     []byte
	RootKey  *hdkeychain.ExtendedKey
	Network  *chaincfg.Params
}

// NewBIP39Wallet 从助记词创建钱包
func NewBIP39Wallet(mnemonic, passphrase, network string) (*BIP39Wallet, error) {
	// 验证助记词
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	// 获取网络参数
	var params *chaincfg.Params
	switch network {
	case "mainnet":
		params = &chaincfg.MainNetParams
	case "testnet":
		params = &chaincfg.TestNet3Params
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}

	// 生成种子
	seed := bip39.NewSeed(mnemonic, passphrase)

	// 生成主密钥
	masterKey, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %v", err)
	}

	return &BIP39Wallet{
		Mnemonic: mnemonic,
		Seed:     seed,
		RootKey:  masterKey,
		Network:  params,
	}, nil
}

// DeriveBIP44Account 派生BIP44账户
func (w *BIP39Wallet) DeriveBIP44Account(account, change uint32) (*hdkeychain.ExtendedKey, error) {
	// BIP44路径: m/44'/coin_type'/account'/change
	// 比特币主网coin_type=0，测试网coin_type=1
	coinType := uint32(0)
	if w.Network.Name == chaincfg.TestNet3Params.Name {
		coinType = 1
	}

	// 派生路径
	path := []uint32{
		hdkeychain.HardenedKeyStart + 44, // purpose
		hdkeychain.HardenedKeyStart + coinType,
		hdkeychain.HardenedKeyStart + account,
		change,
	}

	currentKey := w.RootKey
	for _, index := range path {
		var err error
		currentKey, err = currentKey.Derive(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive at index %d: %v", index, err)
		}
	}

	return currentKey, nil
}

// DeriveBIP49Account 派生BIP49账户 (P2SH-wrapped SegWit)
func (w *BIP39Wallet) DeriveBIP49Account(account, change uint32) (*hdkeychain.ExtendedKey, error) {
	// BIP49路径: m/49'/coin_type'/account'/change
	coinType := uint32(0)
	if w.Network.Name == chaincfg.TestNet3Params.Name {
		coinType = 1
	}

	path := []uint32{
		hdkeychain.HardenedKeyStart + 49, // purpose for P2SH-wrapped segwit
		hdkeychain.HardenedKeyStart + coinType,
		hdkeychain.HardenedKeyStart + account,
		change,
	}

	currentKey := w.RootKey
	for _, index := range path {
		var err error
		currentKey, err = currentKey.Derive(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive at index %d: %v", index, err)
		}
	}

	return currentKey, nil
}

// DeriveBIP84Account 派生BIP84账户 (Native SegWit)
func (w *BIP39Wallet) DeriveBIP84Account(account, change uint32) (*hdkeychain.ExtendedKey, error) {
	// BIP84路径: m/84'/coin_type'/account'/change
	coinType := uint32(0)
	if w.Network.Name == chaincfg.TestNet3Params.Name {
		coinType = 1
	}

	path := []uint32{
		hdkeychain.HardenedKeyStart + 84, // purpose for native segwit
		hdkeychain.HardenedKeyStart + coinType,
		hdkeychain.HardenedKeyStart + account,
		// change,
	}

	currentKey := w.RootKey
	for _, index := range path {
		var err error
		currentKey, err = currentKey.Derive(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive at index %d: %v", index, err)
		}
	}

	return currentKey, nil
}

// DeriveBIP86Account 派生BIP86账户 (Taproot)
func (w *BIP39Wallet) DeriveBIP86Account(account, change uint32) (*hdkeychain.ExtendedKey, error) {
	// BIP86路径: m/86'/coin_type'/account'/change
	coinType := uint32(0)
	if w.Network.Name == chaincfg.TestNet3Params.Name {
		coinType = 1
	}

	path := []uint32{
		hdkeychain.HardenedKeyStart + 86, // purpose for taproot
		hdkeychain.HardenedKeyStart + coinType,
		hdkeychain.HardenedKeyStart + account,
		change,
	}

	currentKey := w.RootKey
	for _, index := range path {
		var err error
		currentKey, err = currentKey.Derive(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive at index %d: %v", index, err)
		}
	}

	return currentKey, nil
}
