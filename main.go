package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/blockchainspectre/go-bip32"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/cosmos/go-bip39"
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

	// 从指纹和深度构建路径
	// 注意：我们没有完整的路径信息，只能构建占位符
	path := "m"
	for i := uint8(0); i < key.Depth(); i++ {
		// 如果是最后一层，使用实际的子编号
		if i == key.Depth()-1 {
			if key.ChildIndex() >= hdkeychain.HardenedKeyStart {
				path += fmt.Sprintf("/%d'", key.ChildIndex()-hdkeychain.HardenedKeyStart)
			} else {
				path += fmt.Sprintf("/%d", key.ChildIndex())
			}
		} else {
			// 其他层用占位符
			path += "/?"
		}
	}

	return path
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
	// 创建见证程序
	witnessProgram := []byte{0x00, 0x14}
	witnessProgram = append(witnessProgram, pubKeyHash...)

	// 创建赎回脚本
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

// TaprootAnalyzer Taproot分析器
type TaprootAnalyzer struct {
	NetParams *chaincfg.Params
}

// NewTaprootAnalyzer 创建Taproot分析器
func NewTaprootAnalyzer(network string) (*TaprootAnalyzer, error) {
	analyzer, err := NewXpubAnalyzer(network)
	if err != nil {
		return nil, err
	}

	return &TaprootAnalyzer{
		NetParams: analyzer.NetParams,
	}, nil
}

// DeriveTaprootAddress 从xpub派生Taproot地址
func (t *TaprootAnalyzer) DeriveTaprootAddress(xpubStr string, index uint32) (string, error) {
	// 使用XpubAnalyzer派生
	analyzer, _ := NewXpubAnalyzer(t.NetParams.Name)

	// 派生指定索引的子密钥
	childInfo, err := analyzer.DeriveChild(xpubStr, index)
	if err != nil {
		return "", err
	}

	// 获取公钥
	pubKeyBytes, err := hex.DecodeString(childInfo.PublicKey)
	if err != nil {
		return "", err
	}

	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return "", err
	}

	// 计算Taproot地址
	// 对于单签名，我们直接使用公钥的x-only坐标
	xOnlyPubKey := pubKey.SerializeCompressed()[1:] // 移除奇偶字节，取x坐标

	// 创建Taproot输出脚本
	taprootScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(xOnlyPubKey).
		Script()
	if err != nil {
		return "", err
	}

	// 创建Taproot地址
	taprootHash := sha256.Sum256(taprootScript[2:]) // 跳过OP_1和长度字节
	address, err := btcutil.NewAddressTaproot(taprootHash[:], t.NetParams)
	if err != nil {
		return "", err
	}

	return address.EncodeAddress(), nil
}

// GenerateTaprootDescriptor 生成Taproot描述符
func (t *TaprootAnalyzer) GenerateTaprootDescriptor(xpubStr, fingerprint, path string) string {
	return fmt.Sprintf("tr([%s/%s]%s/<0;1>/*)", fingerprint, path, xpubStr)
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

func main1() {
	// 示例1: 测试网xpub解析
	fmt.Println("EXAMPLE 1: Parsing a testnet xpub")
	fmt.Println(strings.Repeat("=", 50))

	analyzer, err := NewXpubAnalyzer("testnet")
	if err != nil {
		fmt.Printf("Failed to create analyzer: %v\n", err)
		return
	}

	// 测试网xpub
	xpub1 := "vpub5YJBHKht9RDPsD7XasBepbiR395Xhs4a92a1Zwn3iL8akboDafJYJLM4v1VAh8atKnxuqbBxm6Wwave4AMNr4HLjuBqK9TdXRfumd7ueZui"

	info1, err := analyzer.ParseXpub(xpub1)
	if err != nil {
		fmt.Printf("Failed to parse xpub: %v\n", err)
		return
	}

	DisplayInfo(info1)

	// 示例2: 派生演示
	fmt.Println("\nEXAMPLE 2: Deriving child keys")
	fmt.Println(strings.Repeat("=", 50))

	// 派生第一个子密钥 (非强化)
	childInfo, err := analyzer.DeriveChild(xpub1, 0)
	if err != nil {
		fmt.Printf("Failed to derive child: %v\n", err)
	} else {
		fmt.Printf("Derived Child 0:\n")
		fmt.Printf("  Path: %s/0\n", info1.DerivationPath)
		fmt.Printf("  XPub: %s\n", childInfo.Raw)
		fmt.Printf("  Address (P2WPKH): %s\n", childInfo.AddressP2WPKH)
		fmt.Println()
	}

	// 派生第二个子密钥
	childInfo2, err := analyzer.DeriveChild(xpub1, 1)
	if err != nil {
		fmt.Printf("Failed to derive child 1: %v\n", err)
	} else {
		fmt.Printf("Derived Child 1:\n")
		fmt.Printf("  Path: %s/1\n", info1.DerivationPath)
		fmt.Printf("  Address (P2WPKH): %s\n", childInfo2.AddressP2WPKH)
		fmt.Println()
	}

	// 示例3: 主网xpub解析
	fmt.Println("\nEXAMPLE 3: Parsing a mainnet xpub")
	fmt.Println(strings.Repeat("=", 50))

	mainnetAnalyzer, err := NewXpubAnalyzer("mainnet")
	if err != nil {
		fmt.Printf("Failed to create mainnet analyzer: %v\n", err)
		return
	}

	// 主网xpub示例 (BIP84 - 原生SegWit)
	xpub2 := "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"

	info2, err := mainnetAnalyzer.ParseXpub(xpub2)
	if err != nil {
		fmt.Printf("Failed to parse mainnet xpub: %v\n", err)
	} else {
		fmt.Printf("Successfully parsed mainnet xpub (BIP84)\n")
		fmt.Printf("Key Type: %s\n", info2.KeyType)
		fmt.Printf("Derivation Path: %s\n", info2.DerivationPath)
		fmt.Printf("Address (Native SegWit): %s\n", info2.AddressP2WPKH)
		fmt.Println()
	}

	// 示例4: 根据路径派生
	fmt.Println("\nEXAMPLE 4: Deriving from path")
	fmt.Println(strings.Repeat("=", 50))

	path := "0/0" // 从给定的xpub派生，路径是相对于xpub的
	derivedInfo, err := analyzer.DeriveFromPath(xpub1, "m/"+path)
	if err != nil {
		fmt.Printf("Failed to derive from path: %v\n", err)
	} else {
		fmt.Printf("Derived from path m/%s:\n", path)
		fmt.Printf("  Full Path: %s/%s\n", info1.DerivationPath, path)
		fmt.Printf("  Address (P2WPKH): %s\n", derivedInfo.AddressP2WPKH)
		fmt.Println()
	}

	// 示例5: 解析描述符
	fmt.Println("\nEXAMPLE 5: Parsing descriptors")
	fmt.Println(strings.Repeat("=", 50))

	// Taproot 描述符
	descriptor1 := "tr([092fa4f8/86'/1'/0']tpubDDUoGjUZLVSb95WQC3UDu4hgugkkG8cShUawrx9jfsnuqi79Z5h86GqT5vP1YDjJKtNX1DDvYSSejJwuFd4XqNfurGcAi4eouu5tSHAGtoe/<0;1>/*)"

	descInfo1, err := analyzer.ParseDescriptor(descriptor1)
	if err != nil {
		fmt.Printf("Failed to parse descriptor: %v\n", err)
	} else {
		DisplayDescriptorInfo(descInfo1)

		// 解析描述符中的xpub
		if descInfo1.XPub != "" {
			xpubInfo, err := analyzer.ParseXpub(descInfo1.XPub)
			if err != nil {
				fmt.Printf("Failed to parse xpub from descriptor: %v\n", err)
			} else {
				fmt.Printf("XPub from descriptor:\n")
				fmt.Printf("  Depth: %d\n", xpubInfo.Depth)
				fmt.Printf("  Child Number: %d\n", xpubInfo.ChildNumber)
				fmt.Printf("  Parent Fingerprint: %s\n", xpubInfo.ParentFingerprint)
			}
		}
	}

	// 另一个描述符示例
	descriptor2 := "wpkh([d34db33f/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)"

	fmt.Println("\nAnother descriptor example:")
	descInfo2, err := mainnetAnalyzer.ParseDescriptor(descriptor2)
	if err != nil {
		fmt.Printf("Failed to parse descriptor: %v\n", err)
	} else {
		DisplayDescriptorInfo(descInfo2)
	}

	// 示例6: 批量生成地址
	fmt.Println("\nEXAMPLE 6: Batch address generation")
	fmt.Println(strings.Repeat("=", 50))

	// 生成前5个接收地址
	fmt.Println("First 5 receive addresses:")
	for i := uint32(0); i < 5; i++ {
		childInfo, err := analyzer.DeriveChild(xpub1, i)
		if err != nil {
			fmt.Printf("  Failed to derive child %d: %v\n", i, err)
			continue
		}
		fmt.Printf("  %d: %s (P2WPKH)\n", i, childInfo.AddressP2WPKH)
	}

	// 生成前5个找零地址 (通常使用内部分支，索引从1开始)
	fmt.Println("\nFirst 5 change addresses (derivation path /1/*):")
	changeXpub, err := analyzer.DeriveChild(xpub1, 1)
	if err != nil {
		fmt.Printf("Failed to derive change branch: %v\n", err)
	} else {
		for i := uint32(0); i < 5; i++ {
			changeAddr, err := analyzer.DeriveChild(changeXpub.Raw, i)
			if err != nil {
				fmt.Printf("  Failed to derive change address %d: %v\n", i, err)
				continue
			}
			fmt.Printf("  %d: %s (P2WPKH)\n", i, changeAddr.AddressP2WPKH)
		}
	}
}

func main() {
	// 生成助记词
	// mnemonic, err := GenerateMnemonic(128)
	// if err != nil {
	// 	fmt.Printf("Failed to generate mnemonic: %v\n", err)
	// 	return
	// }
	mnemonic := "spoil fine just umbrella victory organ reform scrub filter rigid mouse dry"

	fmt.Printf("Mnemonic: %s\n", mnemonic)

	// 创建钱包
	wallet, err := NewBIP39Wallet(mnemonic, "", "testnet")
	if err != nil {
		fmt.Printf("Failed to create wallet: %v\n", err)
		return
	}

	// 派生账户
	accountKey, err := wallet.DeriveBIP44Account(0, 0)
	if err != nil {
		fmt.Printf("Failed to derive account: %v\n", err)
		return
	}
	accountAddress, err := accountKey.Address(wallet.Network)
	if err != nil {
		fmt.Printf("Failed to get account address: %v\n", err)
		return
	}
	fmt.Println("accountAddress:", accountAddress)

	// 获取xpub
	xpub, err := accountKey.Neuter()
	if err != nil {
		fmt.Printf("Failed to neuter key: %v\n", err)
		return
	}

	xpubStr := xpub.String()

	fmt.Printf("Account XPUB: %s\n", xpubStr)

	// 解析xpub
	analyzer, _ := NewXpubAnalyzer("testnet")
	info, err := analyzer.ParseXpub(xpubStr)
	if err != nil {
		fmt.Printf("Failed to parse xpub: %v\n", err)
		return
	}

	DisplayInfo(info)
}
