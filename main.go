package main

import (
	"fmt"
)

func main() {
	// 生成助记词
	mnemonic, err := GenerateMnemonic(128)
	if err != nil {
		fmt.Printf("Failed to generate mnemonic: %v\n", err)
		return
	}

	fmt.Printf("Mnemonic: %s\n", mnemonic)

	// 创建钱包
	wallet, err := NewBIP39Wallet(mnemonic, "", "testnet")
	if err != nil {
		fmt.Printf("Failed to create wallet: %v\n", err)
		return
	}

	// 派生BIP84账户 (Native SegWit)
	accountKey, err := wallet.DeriveBIP84Account(0, 0)
	if err != nil {
		fmt.Printf("Failed to derive BIP84 account: %v\n", err)
		return
	}

	// 派生第一个地址 (索引0)
	firstAddrKey, err := accountKey.Derive(0)
	if err != nil {
		fmt.Printf("Failed to derive first address: %v\n", err)
		return
	}

	// 获取公钥
	pubKey, err := firstAddrKey.ECPubKey()
	if err != nil {
		fmt.Printf("Failed to get public key: %v\n", err)
		return
	}

	// 生成四种类型的地址
	addresses, err := GenerateAddressesFromCompressedPubKey(pubKey.SerializeCompressed(), wallet.Network)
	if err != nil {
		fmt.Printf("Failed to generate addresses: %v\n", err)
		return
	}

	fmt.Println("Generated Bitcoin Addresses:")
	fmt.Printf("P2PKH (Legacy):      %s\n", addresses.P2PKH)
	fmt.Printf("P2SH-P2WPKH:         %s\n", addresses.P2SH_P2WPKH)
	fmt.Printf("P2WPKH (SegWit):     %s\n", addresses.P2WPKH)
	fmt.Printf("P2TR (Taproot):      %s\n", addresses.P2TR)

	// 获取xpub
	xpub, err := firstAddrKey.Neuter()
	if err != nil {
		fmt.Printf("Failed to neuter key: %v\n", err)
		return
	}

	xpubStr := xpub.String()
	fmt.Printf("BIP84 Account XPUB: %s\n", xpubStr)

	// 解析xpub
	{
		analyzer, err := NewXpubAnalyzer("testnet")
		if err != nil {
			fmt.Printf("Failed to create analyzer: %v\n", err)
			return
		}
		info, err := analyzer.ParseXpub(xpubStr)
		if err != nil {
			fmt.Printf("Failed to parse xpub: %v\n", err)
			return
		}

		DisplayInfo(info)
	}
}
