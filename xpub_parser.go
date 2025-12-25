package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/blockchainspectre/go-bip32"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// XpubInfo 扩展公钥信息结构体
type XpubInfo struct {
	Raw                string
	Network            string
	KeyType            string
	Depth              uint8
	ParentFingerprint  string
	ChildNumber        uint32
	ChainCode          string
	PublicKey          string
	PublicKeyHash160   string
	Fingerprint        string
	DerivationPath     string
	AddressP2PKH       string
	AddressP2WPKH      string
	AddressP2SH_P2WPKH string
	AddressP2TR        string
	Version            []byte
	IsPrivate          bool
	ExtendedKey        *hdkeychain.ExtendedKey
	BIP32Key           *bip32.Key
}

// DescriptorInfo 描述符解析结果
type DescriptorInfo struct {
	Type        string // wpkh, sh, tr, etc.
	XPub        string
	Derivation  string // e.g., /0/* or /<0;1>/*
	Fingerprint string
	Path        string
}

// DisplayInfo 显示解析结果
func DisplayInfo(info *XpubInfo) {
	fmt.Println("=== Bitcoin Extended Public Key Analysis ===")
	fmt.Printf("Raw XPub: %s\n", info.Raw)
	fmt.Printf("Network: %s\n", info.Network)
	fmt.Printf("Key Type: %s\n", info.KeyType)
	fmt.Printf("Depth: %d\n", info.Depth)
	fmt.Printf("Parent Fingerprint: %s\n", info.ParentFingerprint)
	fmt.Printf("Child Number: %d\n", info.ChildNumber)

	if info.ChildNumber >= hdkeychain.HardenedKeyStart {
		fmt.Printf("  (Hardened: %d)\n", info.ChildNumber-hdkeychain.HardenedKeyStart)
	}

	fmt.Printf("Chain Code: %s\n", info.ChainCode)
	fmt.Printf("Public Key: %s\n", info.PublicKey)
	fmt.Printf("Public Key Hash160: %s\n", info.PublicKeyHash160)
	fmt.Printf("Fingerprint: %s\n", info.Fingerprint)
	fmt.Printf("Derivation Path: %s\n", info.DerivationPath)
	fmt.Printf("Is Private: %v\n", info.IsPrivate)
	fmt.Println()
	fmt.Println("=== Addresses ===")
	fmt.Printf("P2PKH (Legacy): %s\n", info.AddressP2PKH)
	fmt.Printf("P2WPKH (Native SegWit): %s\n", info.AddressP2WPKH)
	fmt.Printf("P2SH-P2WPKH (Nested SegWit): %s\n", info.AddressP2SH_P2WPKH)
	fmt.Printf("P2TR (taproot): %s\n", info.AddressP2TR)
	fmt.Println()

	if info.Version != nil {
		fmt.Printf("Version Bytes: %x\n", info.Version)
	}
}

// DisplayDescriptorInfo 显示描述符解析结果
func DisplayDescriptorInfo(info *DescriptorInfo) {
	fmt.Println("=== Descriptor Analysis ===")
	fmt.Printf("Type: %s\n", info.Type)
	if info.Fingerprint != "" {
		fmt.Printf("Fingerprint: %s\n", info.Fingerprint)
	}
	if info.Path != "" {
		fmt.Printf("Path: %s\n", info.Path)
	}
	fmt.Printf("XPub: %s\n", info.XPub)
	if info.Derivation != "" {
		fmt.Printf("Derivation: %s\n", info.Derivation)
	}
	fmt.Println()
}

// XpubAnalyzer 扩展公钥分析器
type XpubAnalyzer struct {
	NetParams *chaincfg.Params
}

// NewXpubAnalyzer 创建分析器
func NewXpubAnalyzer(network string) (*XpubAnalyzer, error) {
	var params *chaincfg.Params

	switch strings.ToLower(network) {
	case "mainnet", "main":
		params = &chaincfg.MainNetParams
	case "testnet", "testnet3", "test":
		params = &chaincfg.TestNet3Params
	case "regtest", "reg":
		params = &chaincfg.RegressionNetParams
	case "signet", "sig":
		params = &chaincfg.SigNetParams
	default:
		return nil, fmt.Errorf("unknown network: %s", network)
	}

	return &XpubAnalyzer{
		NetParams: params,
	}, nil
}

// ParseXpub 解析扩展公钥
func (a *XpubAnalyzer) ParseXpub(xpubStr string) (*XpubInfo, error) {
	// 方法1: 使用 btcd 的 hdkeychain 解析
	extKey, err := hdkeychain.NewKeyFromString(xpubStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse with hdkeychain: %v", err)
	}

	// 获取基本信息
	depth := extKey.Depth()
	parentFP := extKey.ParentFingerprint()
	childNum := extKey.ChildIndex()

	// 获取公钥
	pubKey, err := extKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %v", err)
	}

	// 转换为压缩公钥
	compressedPubKey := pubKey.SerializeCompressed()

	// 计算公钥哈希 (Hash160)
	pubKeyHash := btcutil.Hash160(compressedPubKey)

	// 计算指纹 (前4字节的Hash160)
	fingerprint := pubKeyHash[:4]

	// 获取链码
	chainCode := extKey.ChainCode()

	// 确定网络和类型
	network, keyType := a.identifyKeyType(xpubStr)

	// 计算派生路径
	derivationPath := a.calculateDerivationPath(extKey)

	// 生成各种地址
	addressP2PKH, err := a.generateP2PKHAddress(pubKeyHash)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P2PKH address: %v", err)
	}

	addressP2WPKH, err := a.generateP2WPKHAddress(pubKeyHash)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P2WPKH address: %v", err)
	}

	addressP2SH_P2WPKH, err := a.generateP2SH_P2WPKHAddress(pubKeyHash)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P2SH-P2WPKH address: %v", err)
	}

	addressP2TR, err := a.generateP2TRAddress(compressedPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P2TR address: %v", err)
	}

	// 构建结果
	info := &XpubInfo{
		Raw:                xpubStr,
		Network:            network,
		KeyType:            keyType,
		Depth:              depth,
		ParentFingerprint:  fmt.Sprintf("%08x", parentFP),
		ChildNumber:        childNum,
		ChainCode:          hex.EncodeToString(chainCode),
		PublicKey:          hex.EncodeToString(compressedPubKey),
		PublicKeyHash160:   hex.EncodeToString(pubKeyHash),
		Fingerprint:        hex.EncodeToString(fingerprint),
		DerivationPath:     derivationPath,
		AddressP2PKH:       addressP2PKH,
		AddressP2WPKH:      addressP2WPKH,
		AddressP2SH_P2WPKH: addressP2SH_P2WPKH,
		AddressP2TR:        addressP2TR,
		IsPrivate:          extKey.IsPrivate(),
		ExtendedKey:        extKey,
	}

	// 同时用 go-bip32 解析以获取更多信息
	bip32Key, err := bip32.B58Deserialize(xpubStr)
	if err == nil {
		info.BIP32Key = bip32Key
		info.Version = bip32Key.Version
	}

	return info, nil
}

// identifyKeyType 识别密钥类型
func (a *XpubAnalyzer) identifyKeyType(xpubStr string) (network, keyType string) {
	// 简单识别：根据前缀
	switch {
	case strings.HasPrefix(xpubStr, "xpub"):
		return "mainnet", "xpub"
	case strings.HasPrefix(xpubStr, "xprv"):
		return "mainnet", "xprv"
	case strings.HasPrefix(xpubStr, "tpub"):
		return "testnet", "tpub"
	case strings.HasPrefix(xpubStr, "tprv"):
		return "testnet", "tprv"
	case strings.HasPrefix(xpubStr, "ypub"):
		return "mainnet", "ypub"
	case strings.HasPrefix(xpubStr, "yprv"):
		return "mainnet", "yprv"
	case strings.HasPrefix(xpubStr, "zpub"):
		return "mainnet", "zpub"
	case strings.HasPrefix(xpubStr, "zprv"):
		return "mainnet", "zprv"
	case strings.HasPrefix(xpubStr, "vpub"):
		return "testnet", "vpub"
	case strings.HasPrefix(xpubStr, "vprv"):
		return "testnet", "vprv"
	case strings.HasPrefix(xpubStr, "upub"):
		return "mainnet", "upub" // BIP49 测试网？实际上是BIP84的别名
	case strings.HasPrefix(xpubStr, "uprv"):
		return "mainnet", "uprv"
	default:
		// 尝试从网络参数判断
		if a.NetParams.Name == chaincfg.MainNetParams.Name {
			return "mainnet", "unknown"
		}
		return "testnet", "unknown"
	}
}

// calculateDerivationPath 计算派生路径
func (a *XpubAnalyzer) calculateDerivationPath(key *hdkeychain.ExtendedKey) string {
	if key.Depth() == 0 {
		return "m"
	}

	// 根据xpub前缀、网络类型和深度推断标准路径
	keyType := a.getKeyTypeFromString(key.String())
	depth := key.Depth()
	childIndex := key.ChildIndex()

	// 构建标准BIP路径
	path := a.buildStandardPath(keyType, depth, childIndex)
	return path
}

// getKeyTypeFromString 从xpub字符串获取密钥类型
func (a *XpubAnalyzer) getKeyTypeFromString(xpubStr string) string {
	switch {
	case strings.HasPrefix(xpubStr, "xpub"), strings.HasPrefix(xpubStr, "tpub"):
		return "bip44" // P2PKH
	case strings.HasPrefix(xpubStr, "ypub"), strings.HasPrefix(xpubStr, "upub"):
		return "bip49" // P2SH-P2WPKH
	case strings.HasPrefix(xpubStr, "zpub"), strings.HasPrefix(xpubStr, "vpub"):
		return "bip84" // P2WPKH
	default:
		return "unknown"
	}
}

// buildStandardPath 构建标准路径
func (a *XpubAnalyzer) buildStandardPath(keyType string, depth uint8, childIndex uint32) string {
	if depth == 0 {
		return "m"
	}

	// 根据深度和类型构建路径
	switch depth {
	case 1:
		// m/purpose'
		purpose := a.getPurposeFromKeyType(keyType)
		return fmt.Sprintf("m/%d'", purpose)
	case 2:
		// m/purpose'/coin_type'
		purpose := a.getPurposeFromKeyType(keyType)
		coinType := a.getCoinType()
		return fmt.Sprintf("m/%d'/%d'", purpose, coinType)
	case 3:
		// m/purpose'/coin_type'/account'
		purpose := a.getPurposeFromKeyType(keyType)
		coinType := a.getCoinType()
		account := childIndex
		if account >= hdkeychain.HardenedKeyStart {
			account -= hdkeychain.HardenedKeyStart
			return fmt.Sprintf("m/%d'/%d'/%d'", purpose, coinType, account)
		}
		return fmt.Sprintf("m/%d'/%d'/%d", purpose, coinType, account)
	case 4:
		// m/purpose'/coin_type'/account'/change
		purpose := a.getPurposeFromKeyType(keyType)
		coinType := a.getCoinType()
		return fmt.Sprintf("m/%d'/%d'/i'/%d", purpose, coinType, childIndex)
	case 5:
		// m/purpose'/coin_type'/account'/change/address_index
		purpose := a.getPurposeFromKeyType(keyType)
		coinType := a.getCoinType()
		return fmt.Sprintf("m/%d'/%d'/i'/i/%d", purpose, coinType, childIndex)
	default:
		// 超过5层，使用占位符
		path := "m"
		for i := uint8(0); i < depth; i++ {
			if i == depth-1 {
				if childIndex >= hdkeychain.HardenedKeyStart {
					path += fmt.Sprintf("/%d'", childIndex-hdkeychain.HardenedKeyStart)
				} else {
					path += fmt.Sprintf("/%d", childIndex)
				}
			} else {
				path += "/i"
			}
		}
		return path
	}
}

// getPurposeFromKeyType 根据密钥类型获取purpose值
func (a *XpubAnalyzer) getPurposeFromKeyType(keyType string) uint32 {
	switch keyType {
	case "bip44":
		return 44
	case "bip49":
		return 49
	case "bip84":
		return 84
	case "bip86":
		return 86
	default:
		return 44 // 默认BIP44
	}
}

// getCoinType 根据网络获取coin_type
func (a *XpubAnalyzer) getCoinType() uint32 {
	if a.NetParams.Name == chaincfg.MainNetParams.Name {
		return 0 // Bitcoin mainnet
	}
	return 1 // Bitcoin testnet
}

// generateP2PKHAddress 生成P2PKH地址
func (a *XpubAnalyzer) generateP2PKHAddress(pubKeyHash []byte) (string, error) {
	address, err := btcutil.NewAddressPubKeyHash(pubKeyHash, a.NetParams)
	if err != nil {
		return "", err
	}
	return address.EncodeAddress(), nil
}

// generateP2WPKHAddress 生成原生SegWit地址
func (a *XpubAnalyzer) generateP2WPKHAddress(pubKeyHash []byte) (string, error) {
	address, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, a.NetParams)
	if err != nil {
		return "", err
	}
	return address.EncodeAddress(), nil
}

// generateP2SH_P2WPKHAddress 生成P2SH嵌套SegWit地址
func (a *XpubAnalyzer) generateP2SH_P2WPKHAddress(pubKeyHash []byte) (string, error) {
	// 创建赎回脚本 (witness程序: OP_0 + 20字节公钥哈希)
	redeemScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_0).
		AddData(pubKeyHash).
		Script()
	if err != nil {
		return "", err
	}

	// 计算赎回脚本的哈希
	redeemScriptHash := btcutil.Hash160(redeemScript)

	// 创建P2SH地址
	address, err := btcutil.NewAddressScriptHashFromHash(redeemScriptHash, a.NetParams)
	if err != nil {
		return "", err
	}

	return address.EncodeAddress(), nil
}

// generateP2WPKHAddress 生成原生SegWit地址
func (a *XpubAnalyzer) generateP2TRAddress(compressedPubKey []byte) (string, error) {
	pubkey, err := btcec.ParsePubKey(compressedPubKey)
	if err != nil {
		return "", err
	}
	address, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(
		txscript.ComputeTaprootKeyNoScript(
			pubkey)), a.NetParams)
	if err != nil {
		return "", err
	}
	return address.EncodeAddress(), nil
}

// DeriveChild 派生指定索引的子密钥
func (a *XpubAnalyzer) DeriveChild(xpubStr string, index uint32) (*XpubInfo, error) {
	// 解析父密钥
	parentKey, err := hdkeychain.NewKeyFromString(xpubStr)
	if err != nil {
		return nil, err
	}

	// 检查是否为私钥
	if parentKey.IsPrivate() {
		return nil, errors.New("cannot derive from private key in this context")
	}

	// 派生子密钥
	childKey, err := parentKey.Derive(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive child key: %v", err)
	}

	// 解析子密钥
	childXpubStr := childKey.String()

	return a.ParseXpub(childXpubStr)
}

// DeriveFromPath 根据路径派生
func (a *XpubAnalyzer) DeriveFromPath(xpubStr, path string) (*XpubInfo, error) {
	if !strings.HasPrefix(path, "m/") {
		return nil, errors.New("path must start with 'm/'")
	}

	// 移除开头的 'm/'
	pathParts := strings.Split(path[2:], "/")

	// 解析根密钥
	currentKey, err := hdkeychain.NewKeyFromString(xpubStr)
	if err != nil {
		return nil, err
	}

	// 遍历路径派生
	for _, part := range pathParts {
		if part == "" {
			continue
		}

		// 解析索引
		var index uint32
		var hardened bool

		if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") {
			// 硬化派生
			hardened = true
			part = strings.TrimSuffix(strings.TrimSuffix(part, "'"), "h")

			// 解析数字
			var n uint32
			_, err := fmt.Sscanf(part, "%d", &n)
			if err != nil {
				return nil, fmt.Errorf("invalid path component: %s", part)
			}

			index = n + hdkeychain.HardenedKeyStart
		} else {
			// 正常派生
			hardened = false

			var n uint32
			_, err := fmt.Sscanf(part, "%d", &n)
			if err != nil {
				return nil, fmt.Errorf("invalid path component: %s", part)
			}

			index = n
		}

		// 派生
		if hardened && !currentKey.IsPrivate() {
			return nil, fmt.Errorf("cannot derive hardened child from public key at: %s", part)
		}

		currentKey, err = currentKey.Derive(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive at %s: %v", part, err)
		}
	}

	// 解析最终密钥
	finalXpubStr := currentKey.String()

	return a.ParseXpub(finalXpubStr)
}

// ParseDescriptor 解析描述符
func (a *XpubAnalyzer) ParseDescriptor(descriptor string) (*DescriptorInfo, error) {
	// 简化描述符解析，支持常见格式
	descriptor = strings.TrimSpace(descriptor)

	// 检查是否是包裹的描述符
	if strings.HasSuffix(descriptor, ")") {
		// 查找开头的函数名
		openParen := strings.Index(descriptor, "(")
		if openParen == -1 {
			return nil, errors.New("invalid descriptor format")
		}

		descType := descriptor[:openParen]
		content := descriptor[openParen+1 : len(descriptor)-1]

		info := &DescriptorInfo{
			Type: descType,
		}

		// 检查是否有密钥源 [fingerprint/path]
		if strings.HasPrefix(content, "[") {
			closeBracket := strings.Index(content, "]")
			if closeBracket == -1 {
				return nil, errors.New("invalid key origin format")
			}

			keyOrigin := content[1:closeBracket]
			rest := content[closeBracket+1:]

			// 解析密钥源
			parts := strings.Split(keyOrigin, "/")
			if len(parts) >= 2 {
				info.Fingerprint = parts[0]
				info.Path = "m/" + strings.Join(parts[1:], "/")
			}

			// 解析剩余的
			// 查找派生模式
			slashIdx := strings.Index(rest, "/")
			if slashIdx != -1 {
				info.XPub = rest[:slashIdx]
				info.Derivation = rest[slashIdx:]
			} else {
				info.XPub = rest
				info.Derivation = ""
			}
		} else {
			// 没有密钥源
			slashIdx := strings.Index(content, "/")
			if slashIdx != -1 {
				info.XPub = content[:slashIdx]
				info.Derivation = content[slashIdx:]
			} else {
				info.XPub = content
				info.Derivation = ""
			}
		}

		return info, nil
	}

	return nil, errors.New("unsupported descriptor format")
}
