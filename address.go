package main

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// BitcoinAddresses 比特币地址集合
type BitcoinAddresses struct {
	P2PKH       string // Legacy地址
	P2SH_P2WPKH string // P2SH包装的SegWit地址
	P2WPKH      string // Native SegWit地址
	P2TR        string // Taproot地址
}

// GenerateAddressesFromCompressedPubKey 从压缩公钥生成四种类型的比特币地址
func GenerateAddressesFromCompressedPubKey(compressedPubKey []byte, network *chaincfg.Params) (*BitcoinAddresses, error) {
	// 解析公钥
	pubKey, err := btcec.ParsePubKey(compressedPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	_ = pubKey

	addresses := &BitcoinAddresses{}

	// 1. P2PKH (Legacy地址)
	pubKeyHash := btcutil.Hash160(compressedPubKey)
	p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, network)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2PKH address: %v", err)
	}
	addresses.P2PKH = p2pkhAddr.EncodeAddress()

	// 2. P2WPKH (Native SegWit地址)
	p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, network)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2WPKH address: %v", err)
	}
	addresses.P2WPKH = p2wpkhAddr.EncodeAddress()

	// 3. P2SH-P2WPKH (P2SH包装的SegWit地址)
	witnessScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(pubKeyHash).
		Script()
	if err != nil {
		return nil, fmt.Errorf("failed to create witness script: %v", err)
	}

	scriptHash := btcutil.Hash160(witnessScript)
	p2shAddr, err := btcutil.NewAddressScriptHashFromHash(scriptHash, network)
	if err != nil {
		return nil, fmt.Errorf("failed to create P2SH address: %v", err)
	}
	addresses.P2SH_P2WPKH = p2shAddr.EncodeAddress()

	// // 4. P2TR (Taproot地址)
	addressTaproot, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(
		txscript.ComputeTaprootKeyNoScript(
			pubKey)), network)
	addresses.P2TR = addressTaproot.EncodeAddress()

	return addresses, nil
}
