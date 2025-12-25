package main

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

func TestGenXpubKey(t *testing.T) {
	mnemonic := "spoil fine just umbrella victory organ reform scrub filter rigid mouse dry"

	fmt.Printf("Mnemonic: %s\n", mnemonic)

	// 创建钱包
	wallet, err := NewBIP39Wallet(mnemonic, "", "testnet")
	if err != nil {
		fmt.Printf("Failed to create wallet: %v\n", err)
		return
	}

	// 派生BIP84账户 (Native SegWit)
	accountKey, err := wallet.DeriveBIP44Account(0, 0)
	if err != nil {
		fmt.Printf("Failed to derive BIP84 account: %v\n", err)
		return
	}

	pXpub, err := accountKey.Neuter()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("ParentXpubKey:", pXpub.String())

	// 派生第一个地址 (索引0)
	firstAddrKey, err := accountKey.Derive(0)
	if err != nil {
		fmt.Printf("Failed to derive first address: %v\n", err)
		return
	}
	pXpub, err = firstAddrKey.Neuter()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("XpubKey:", pXpub.String())

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
}

func TestParseDescriptor(t *testing.T) {
	descriptor := "tr([e7da4e9f/86'/0'/0']xpub6CMZKGF2nrMUNqTmCQ5AjLd5x6peHPvuDWEWk22tw9znE76nekTNJuzedCVqFwhDf7CvBXJgv1FUu7snjcHftejJJEXXq4zLxanh7kmDmix/<0;1>/*)"
	analyzer, err := NewXpubAnalyzer("testnet")
	if err != nil {
		t.Fatal(err)
	}
	rlt, err := analyzer.ParseDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	DisplayDescriptorInfo(rlt)
}

func TestParseXpub(t *testing.T) {
	// m/86/1/0/?/?
	xpubStr := "vpub5YJBHKht9RDPuAgVpsDnoz3KJe2EDhKYc71X4WFnGXeQvxg3HjVkTxYXbT7Kro36su23RP6TrmavYbJ3jXmASuTj9BtwAcj8qrFJ5C55tTg"
	analyzer, err := NewXpubAnalyzer("testnet")
	if err != nil {
		t.Fatal(err)
	}

	extKey, err := hdkeychain.NewKeyFromString(xpubStr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Original xpub depth: %d\n", extKey.Depth())
	fmt.Printf("Original xpub ChildIndex: 0x%x\n", extKey.ChildIndex())
	fmt.Printf("Original xpub: %s\n", extKey.String())

	// 如果depth=5，那么路径可能是 m/86/1/0/0/0
	// 如果depth=3，那么路径是 m/86/1/0
	extKey, _ = extKey.Derive(0)
	extKey, _ = extKey.Derive(0)
	{
		xpub, _ := extKey.Neuter()
		info, err := analyzer.ParseXpub(xpub.String())
		if err != nil {
			t.Fatal(err)
		}

		DisplayInfo(info)
	}

}
