<div align="center">

# Poseidon

![data](https://socialify.git.ci/B1ue1nWh1te/Poseidon/image?font=Rokkitt&forks=1&issues=1&language=1&logo=https%3A%2F%2Fimg.seaeye.cn%2Fimg%2Fseaeye%2Flogo.png&owner=1&pattern=Circuit%20Board&stargazers=1&theme=Light)

**海神波塞冬 Poseidon** 工具对常用的链上交互操作进行了封装，使得开发者能够便捷地

与任何以太坊同构链交互，主要用于在 CTF 比赛中攻克 Blockchain 方向的题目。

[![Lisence](https://img.shields.io/github/license/B1ue1nWh1te/Poseidon)](https://github.com/B1ue1nWh1te/Poseidon/blob/main/LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.7+-blue)](https://www.python.org/)
[![Release](https://img.shields.io/github/v/release/B1ue1nWh1te/Poseidon?include_prereleases)](https://github.com/B1ue1nWh1te/Poseidon/releases/)
[![Visitors](https://visitor-badge.glitch.me/badge?page_id=B1ue1nWh1te-Poseidon&left_color=gray&right_color=orange)](https://github.com/B1ue1nWh1te/Poseidon)

</div>

# 注意事项

1. **本工具仅可用于 CTF 比赛解题，请勿在任何其他场景下使用。**

2. 请尽可能使用最新版本解题。

3. 在使用 `Blockchain` 模块时，你始终应该使用全新生成的账户，而不是导入常用的具有实际价值的账户，以确保你的账户安全。

4. `Blockchain` 模块的所有功能在`Goerli`测试网络中均正常通过检验。

5. 如果你在使用过程中遇到了其他问题，或者有任何好的想法和建议，欢迎提[issue](https://github.com/B1ue1nWh1te/Poseidon/issues)进行反馈。

# 安装

```bash
pip install -U poseidon-python
```

# 现有功能

## Blockchain 模块

本模块可用于与任何以太坊同构链（即通常所说的 EVM 兼容链）进行交互，支持常用的链上交互操作。

基于[Web3.py](https://github.com/ethereum/web3.py)实现。

基本的使用方法可以参考我之前参加比赛时写的 WriteUps：

- [VNCTF 2023 Blockchain Writeup](https://www.seaeye.cn/archives/497.html)
- [第五届“强网”拟态防御国际精英挑战赛线上预选赛 区块链方向题解](https://www.seaeye.cn/archives/487.html)
- [2023 RealWorldCTF 体验赛 Blockchain Writeup](https://www.seaeye.cn/archives/494.html)

```python
from Poseidon.Blockchain import *
```

### Chain 类

Chain 是区块链实例，作为链上交互的基础。

`Chain(RPCUrl: str, RequestParams: dict = None)`：

```
初始化。当连接失败时会抛出异常。

参数：
	RPCUrl (str): 链 RPC 地址
	RequestParams (可选)(dict): 指定连接时使用的 request 参数，默认为 None。
	例如当需要使用代理进行访问时，则传入 RequestParams={"proxies": {"http": "http://127.0.0.1:<ProxyPort>","https": "http://127.0.0.1:<ProxyPort>"}}

成员变量：
	Net (Web3.HTTPProvider): web3.py 原生的链交互器对象
	ChainId (int): 链 ID
	ClientVersion (str): 链 RPC 的客户端软件版本号
```

<br>

`GetBasicInformation() -> dict`：

```
获取链的基本信息。包括链 ID 、区块高度、 GasPrice 、出块间隔、链 RPC 的客户端软件版本号。

返回值：
	BasicInformation (dict): 链的基本信息构成的字典。
	{"ChainId"|"BlockNumber"|"GasPrice"|"Timeslot"|"ClientVersion"}
```

<br>

`GetTransactionInformationByHash(self, TransactionHash: str) -> dict`：

```
根据交易哈希获取交易信息。包括交易哈希、所在区块号、交易索引号、交易状态、交易类型、交易行为、发送者、接收者、(部署的合约地址)、(GasPrice 或 (MaxFeePerGas 和 MaxPriorityFeePerGas))、GasLimit、GasUsed、Nonce、Value、Logs、InputData。

参数：
	TransactionHash (str): 要查询的交易哈希

返回值：
	TransactionInformation (dict): 交易信息构成的字典。当出现异常时返回 None 。
	{"TransactionHash"|"BlockNumber"|"TransactionIndex"|"Status"|"Type"|"Action"|"From"|"To"|("ContractAddress")|<"GasPrice"|("MaxFeePerGas"&"MaxPriorityFeePerGas")>|"GasLimit"|"GasUsed"|"Nonce"|"Value"|"Logs"|"InputData"}
```

<br>

`GetTransactionInformationByBlockIdAndIndex(self, BlockID, TransactionIndex: int) -> dict`：

```
根据区块 ID 和交易在块中的索引来获取交易信息。包括交易哈希、所在区块号、交易索引号、交易状态、交易类型、交易行为、发送者、接收者、(部署的合约地址)、(GasPrice 或 (MaxFeePerGas 和 MaxPriorityFeePerGas))、GasLimit、GasUsed、Nonce、Value、Logs、InputData。

参数：
	BlockID (str|int): 区块 ID 。可为区块号或 'latest', 'earliest', 'pending' 。
	TransactionIndex (int): 交易在块中的索引

返回值：
	TransactionInformation (dict): 交易信息构成的字典。当出现异常时返回 None 。
	{"TransactionHash"|"BlockNumber"|"TransactionIndex"|"Status"|"Type"|"Action"|"From"|"To"|("ContractAddress")|<"GasPrice"|("MaxFeePerGas"&"MaxPriorityFeePerGas")>|"GasLimit"|"GasUsed"|"Nonce"|"Value"|"Logs"|"InputData"}
```

<br>

`GetBalance(Address: str) -> int`：

```
根据账户地址获取其网络原生代币余额。

参数：
	Address (str): 账户地址

返回值：
	Balance (int): 账户网络原生代币余额。单位为 wei ，当出现异常时返回 None 。
```

<br>

`GetCode(Address: str) -> str`：

```
根据合约地址获取其已部署字节码。

参数：
	Address (str): 合约地址

返回值：
	Code (str): 合约已部署字节码。含 0x 前缀的十六进制形式，当出现异常时返回 None 。
```

<br>

`GetStorage(Address: str, Index: int) -> str`：

```
根据合约地址和存储插槽索引获取存储值。

参数：
	Address (str): 合约地址
	SlotIndex (int): 存储插槽索引

返回值：
	Data (str): 存储值。含 0x 前缀的十六进制形式，当出现异常时返回 None 。
```

<br>

`DumpStorage(Address: str, Count: int) -> list`：

```
根据合约地址和指定插槽数量值，从插槽 0 开始批量遍历存储插槽并获取值。

参数：
	Address (str): 合约地址
	Count (int): 指定插槽数量值

返回值：
	Data (List[str]): 存储值列表。含 0x 前缀的十六进制形式，当出现异常时返回 None 。
```

<br>

`GetPublicKeyByTransactionHash(TransactionHash: str) -> tuple`：

```
通过一笔已在链上确认的交易哈希，获取账户公钥。

参数：
	TransactionHash (str): 交易哈希

返回值：
	(Address, PublicKey) (tuple): 由账户地址和账户公钥组成的元组。当出现异常时返回 None 。
```

<br>

### Account 类

Account 是账户实例，作为发起链上调用的基础。

`Account(Chain: Chain, PrivateKey: str)`：

```
初始化。通过私钥导入账户并与 Chain 实例绑定，后续的所有链上调用都会作用在 Chain 实例化表示的链上。当导入账户失败时将会抛出异常。

参数：
	Chain (Poseidon.Blockchain.Chain): 区块链实例
	PrivateKey (str): 账户私钥。不含 0x 前缀的十六进制形式。

成员变量：
	Chain (Poseidon.Blockchain.Chain): 区块链实例
	Address (str): 账户地址
	PrivateKey (str): 账户私钥
```

<br>

`GetSelfBalance() -> int`：

```
获取自身账户的网络原生代币余额。当余额为 0 时会触发无法发送交易的警告。

返回值：
	Balance (int): 自身账户网络原生代币余额。单位为 wei ，当出现异常时返回 None 。
```

<br>

`Transfer(self, To: str, Value: int, GasLimit: int = 100000, Data: str = "0x") -> dict`：

```
向指定账户转账指定数量的网络原生代币，可附带信息。若 90 秒内交易未确认则作超时处理。

参数：
	To (str): 接收方地址
	Value (int): 发送的网络原生代币数量。单位为 wei 。
	GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 100000 wei 。
	Data (可选)(str): 交易数据。含 0x 前缀的十六进制形式，默认值为 "0x" 。

返回值：
	TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
```

<br>

`SendTransaction(To: str, Data: str, Value: int = 0, GasLimit: int = 1000000) -> dict`：

```
以传统方式发送一笔自定义交易。若 90 秒内交易未确认则作超时处理。

参数：
	To (str): 接收方地址
	Data (str): 交易数据。含 0x 前缀的十六进制形式。
	Value (可选)(int): 随交易发送的网络原生代币数量。单位为 wei ，默认为 0 wei 。
	GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 1000000 wei 。

返回值：
	TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
```

<br>

`SendTransactionByEIP1559(To: str, Data: str, Value: int = 0, GasLimit: int = 1000000) -> dict`：

```
以 EIP-1559 方式发送一笔自定义交易。若 90 秒内交易未确认则作超时处理。

参数：
	To (str): 接收方地址
	Data (str): 交易数据。含 0x 前缀的十六进制形式。
	Value (可选)(int): 随交易发送的网络原生代币数量。单位为 wei ，默认为 0 wei 。
	GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 1000000 wei 。

返回值：
	TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
```

<br>

`DeployContract(ABI: dict, Bytecode: str, Value: int = 0, *Arguments) -> dict`：

```
部署合约。若 90 秒内交易未确认则作超时处理。

参数：
	ABI (dict): 合约 ABI
	Bytecode (str): 合约部署字节码。含 0x 前缀的十六进制形式。
	Value (可选)(int): 随交易发送给合约的网络原生代币数量。单位为 wei ，默认为 0 wei 。
	*Arguments (可选)(any): 传给合约构造函数的参数，默认为空。

返回值：
	TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
	当合约部署成功时，字典中会额外添加"Contract"字段，该变量是已实例化的 Contract 对象，失败时为 None。
```

<br>

`DeployContractWithoutABI(Bytecode: str, Value: int = 0, GasLimit: int = 10000000) -> dict`：

```
在没有 ABI 的情况下，仅使用字节码来部署合约。若 90 秒内交易未确认则作超时处理。

参数：
	Bytecode (str): 合约部署字节码。含 0x 前缀的十六进制形式。
	Value (可选)(int): 随交易发送给合约的网络原生代币数量。单位为 wei ，默认为 0 wei 。
	GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 10000000 wei 。

返回值：
	TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
```

<br>

`SignMessage(Message: str) -> dict`：

```
消息字符串进行签名。

参数：
	Message (str): 待签名消息字符串

返回值：
	SignatureData (str): 签名数据构成的字典。当出现异常时返回 None 。
	{"Address"|"Message"|"MessageHash"|"Signature"|"R"|"S"|"V"}
```

<br>

`SignMessageHash(MessageHash: str) -> dict`：

```
对消息哈希进行签名。

参数：
	MessageHash (str): 待签名消息哈希

返回值：
	SignatureData (str): 签名数据构成的字典。当出现异常时返回 None 。
	{"Address"|"MessageHash"|"Signature"|"R"|"S"|"V"}
```

<br>

### Contract 类

Contract 是合约实例，作为与指定合约进行交互的基础。

`Contract(Account: Account, Address: str, ABI: dict)`：

```
初始化。通过合约地址与 ABI 来实例化合约，并与 Account 绑定，后续所有对该合约的调用都会由这一账户发起。当实例化失败时会抛出异常。

参数：
	Account (Poseidon.Blockchain.Account): 账户实例
	Address (str): 合约地址
	ABI (str): 合约 ABI

成员变量：
	Account (Poseidon.Blockchain.Account): 账户实例
	Address (str): 合约地址
	Instance (Web3.eth.Contract): web3.py 原生 contract 对象实例
```

<br>

`CallFunction(FunctionName: str, *FunctionArguments) -> dict`：

```
通过传入函数名及参数来调用该合约内的函数。

参数：
	FunctionName (str): 函数名称
	*FunctionArguments (可选)(any): 函数参数，默认为空。

返回值：
	TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
```

<br>

`CallFunctionWithValueAndGasLimit(Value: int, GasLimit: int, FunctionName: str, *FunctionArguments) -> dict`：

```
通过传入函数名及参数来调用该合约内的函数。支持自定义 Value 和 GasLimit 。

参数：
	Value (int): 随交易发送的网络原生代币数量。单位为 wei 。
	GasLimit (int): Gas 最大使用量。单位为 wei 。
	FunctionName (str): 函数名称
	*FunctionArguments (可选)(any): 函数参数，默认为空。

返回值：
	TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
```

<br>

`ReadOnlyCallFunction(FunctionName: str, *FunctionArguments)`：

```
通过传入函数名及参数来调用该合约内的只读函数。

参数：
	FunctionName (str): 函数名称
	*FunctionArguments (可选)(any): 函数参数，默认为空。

返回值：
	Result (any): 调用函数后得到的返回值。当出现异常时返回 None 。
```

<br>

`EncodeABI(FunctionName: str, *FunctionArguments) -> str`：

```
通过传入函数名及参数进行编码，相当于生成调用该函数的 CallData 。

参数：
	FunctionName (str): 函数名称
	*FunctionArguments (可选)(any): 函数参数，默认为空。

返回值：
	CallData (str): 调用数据编码。含 0x 前缀的十六进制形式。当出现异常时返回 None 。
```

<br>

### BlockchainUtils 类

通用工具，链下使用的功能。

`SwitchSolidityVersion(SolidityVersion: str)`：

```
设置当前使用的 Solidity 版本，若该版本未安装则会自动安装。当设置版本失败时会抛出异常。

参数：
	SolidityVersion (str): Solidity 版本号
```

<br>

`Compile(FileCourse: str, ContractName: str, SolidityVersion: str = None, AllowPaths: str = None, Optimize: bool = False) -> tuple`：

```
根据给定的参数使用 py-solc-x 编译合约。当编译失败时会抛出异常。

参数：
	FileCourse (str): 合约文件完整路径。当合约文件与脚本文件在同一目录下时可直接使用文件名。
	ContractName (str): 要编译的合约名称
	SolidityVersion (可选)(str): 指定使用的 Solidity 版本。若不指定则会使用当前已激活的 Solidity 版本进行编译。默认为 None 。
	AllowPaths (可选)(str): 指定许可路径。在编译时可能会出现 AllowPaths 相关错误可在这里解决。默认为 None 。
	Optimize (可选)(str): 是否开启优化器。默认为 False 。

返回值：
	(ABI, Bytecode) (tuple): 由 ABI 和 Bytecode 组成的元组
```

<br>

`CreateNewAccount() -> tuple`：

```
创建新账户。

返回值：
(Address, PrivateKey) (tuple): 由账户地址和私钥组成的元组
```

<br>

`MnemonicToAddressAndPrivateKey(Mnemonic: str) -> tuple`：

```
将助记词转换为账户地址与私钥。参考 BIP-39 标准。

参数：
	Mnemonic (str): 助记词字符串。以空格进行分隔。

返回值：
	(Address, PrivateKey) (tuple): 由账户地址和私钥组成的元组。当出现异常时返回 None 。
```

<br>

`RecoverMessage(Message: str, Signature: str) -> str`：

```
通过消息原文和签名还原出签署者的账户地址。

参数：
	Message (str): 消息原文
	Signature (str): 签名

返回值：
	Signer (str): 签署者的账户地址。当出现异常时返回 None 。
```

<br>

`RecoverMessageByHash(MessageHash: str, Signature: str) -> str`：

```
通过消息哈希和签名还原出签署者的账户地址。

参数：
	MessageHash (str): 消息哈希
	Signature (str): 签名

返回值：
	Signer (str): 签署者的账户地址。当出现异常时返回 None 。
```

<br>

`RecoverRawTransaction(RawTransactionData: str) -> str`：

```
获取签署此交易的账户地址。

参数：
	RawTransactionData (str): 原生交易数据。含 0x 前缀的十六进制形式。

返回值：
	Address (str): 账户地址。当出现异常时返回 None 。
```

<br>

`CrackSelector(SourceFunctionName: str, SourceFunctionParameters: list, ToGenerateFunctionParameters: list) -> str`：

```
根据源函数名、参数与想要碰撞生成的函数的参数，碰撞生成出一个函数名，以使得这两个函数的选择器签名相等。

参数：
	SourceFunctionName (str): 目标函数名
	SourceFunctionParameters (List[str]): 目标函数参数列表
	ToGenerateFunctionParameters (List[str]): 想要碰撞生成的函数的参数列表

返回值：
	ToGenerateFunction (str): 碰撞出的函数的名称与参数完整表示。当出现异常时返回 None 。
```

<br>

`AssemblyToBytecode(Assembly: str) -> str`：

```
将 EVM Assembly 转为 EVM Bytecode 。

参数：
	Assembly (str): EVM Assembly

返回值：
	Bytecode (str): EVM Bytecode 。含 0x 前缀的六进制形式。当出现异常时返回 None 。
```

<br>

`BytecodeToAssembly(Bytecode: str) -> str`：

```
将 EVM Bytecode 转为 EVM Assembly 。

参数：
	Bytecode (str): EVM Bytecode 。含 0x 前缀的十六进制形式。

返回值：
	Assembly (str): EVM Assembly 。当出现异常时返回 None 。
```

<br>

`SignatureToRSV(Signature: str) -> dict`：

```
将签名解析成 R S V 。

参数：
	Signature (str): 签名。含 0x 前缀的十六进制形式。

返回值：
	Result (dict): 解析结果。当出现异常时返回 None 。
	{"Signature"|"R"|"S"|"V"}
```

<br>

`RSVToSignature(R: str, S: str, V: str) -> dict`：

```
将 R S V 合并成签名。

参数：
	R (str): 签名 r 值。含 0x 前缀的十六进制形式。
	S (str): 签名 s 值。含 0x 前缀的十六进制形式。
	V (str): 签名 v 值。含 0x 前缀的十六进制形式。

返回值：
	Result (dict): 合并结果。当出现异常时返回 None 。
	{"R"|"S"|"V"|"Signature"}
```

<br>

## Cryptography 模块

本模块用于解决常见的密码学问题。

```python
from Poseidon.Cryptography import ModernCryptoUtils, ClassicalCryptoUtils, MiscUtils
```

### ModernCryptoUtils 类

本模块用于解决现代密码学问题。

`Base64_Encrypt(Text: str) -> str`：

```
用于对字符串进行 Base64 编码。

参数：
	Text (str): 待编码的字符串

返回值：
	EncryptedText (str): Base64 编码后的字符串
```

<br>

`Base64_Decrypt(Text: str) -> str`：

```
用于对 Base64 编码的字符串进行解码。

参数：
	Text (str): 待解码的 Base64 编码字符串

返回值：
	DecryptedText (str): Base64 解码后的字符串
```

<br>

`Base32_Encrypt(Text: str) -> str`：

```
用于对字符串进行 Base32 编码。

参数：
	Text (str): 待编码的字符串

返回值：
	EncryptedText (str): Base32 编码后的字符串
```

<br>

`Base32_Decrypt(Text: str) -> str`：

```
用于对 Base32 编码的字符串进行解码。

参数：
	Text (str): 待解码的 Base32 编码字符串

返回值：
	DecryptedText (str): Base32 解码后的字符串
```

<br>

`Base16_Encrypt(Text: str) -> str`：

```
用于对字符串进行 Base16 编码。

参数：
	Text (str): 待编码的字符串

返回值：
	EncryptedText (str): Base16 编码后的字符串
```

<br>

`Base16_Decrypt(Text: str) -> str`：

```
用于对 Base16 编码的字符串进行解码。

参数：
	Text (str): 待解码的 Base16 编码字符串

返回值：
	DecryptedText (str): Base16 解码后的字符串
```

<br>

`AES_Padding(Text: str, BlockSize: int = 16) -> bytes`：

```
用于对字符串进行 zeropadding 处理。

参数：
	Text (str): 待 padding 的字符串
	BlockSize (可选)(int): 块大小（单位为字节），默认为16字节

返回值：
	Fill (bytes): padding 后的字节数据
```

<br>

`AES_Encrypt(Text: str, Key: str, BlockSize: int = 16) -> str`：

```
用于对字符串进行 AES 加密（仅支持 ECB zeropadding 模式）。

参数：
	Text (str): 待进行 AES 加密的字符串
	Key (str): 加密密钥
	BlockSize (可选)(int): 块大小（单位为字节），默认为16字节

返回值：
	EncryptedText (str): AES 加密后的密文（Base64 编码形式）
```

<br>

`AES_Decrypt(Text: str, Key: str, BlockSize: int = 16) -> str`：

```
用于对 AES 密文进行解密（仅支持 ECB zeropadding 模式）。

参数：
	Text (str): 待解密的 AES 密文（Base64 编码形式）
	Key (str): 解密密钥
	BlockSize (可选)(int): 块大小（单位为字节），默认为16字节

返回值：
	DecryptedText (str): AES 解密后得到的原文
```

<br>

`RSA_Encrypt(Text: str, p: int, q: int, e: int) -> str`：

```
用于对字符串进行 RSA 加密。

参数：
	Text (str): 待进行 RSA 加密的字符串
	p (int): p 值
	q (int): q 值
	e (int): e 值

返回值：
	EncryptedText (str): RSA 加密后的密文（ Base64 编码形式）
```

<br>

`RSA_Base64_Decrypt(Base64Text: str, p: int, q: int, e: int) -> str`：

```
用于对 Base64 编码形式的 RSA 密文进行解密。

参数：
	Base64Text (str): 待进行解密的 Base64 编码形式的 RSA 密文
	p (int): p 值
	q (int): q 值
	e (int): e 值

返回值：
	DecryptedText (str): RSA 解密后得到的原文
```

<br>

`RSA_Long_Decrypt(Long: int, p: int, q: int, e: int) -> str`：

```
用于对长整数形式的 RSA 密文进行解密。

参数：
	Long (int): 待进行解密的长整数形式的 RSA 密文
	p (int): p 值
	q (int): q 值
	e (int): e 值

返回值：
	DecryptedText (str): RSA 解密后得到的原文
```

<br>

`RSA_Wiener_Attack(c: int, e: int, n: int) -> str`：

```
用于对长整数形式的 RSA 密文进行维纳攻击并解出原文。

参数：
	c (int): 待进行维纳攻击的长整数形式的 RSA 密文
	e (int): e 值
	n (int): n 值

返回值：
	m (str): RSA 维纳攻击后得到的原文
```

<br>

`RSA_MultiPrime_Attack(c: int, e: int, n: int, primes: list, powers: list = None) -> str`：

```
用于对长整数形式的 RSA 密文进行多素数攻击并解出原文。

参数：
	c (int): 待进行多素数攻击的长整数形式的 RSA 密文
	e (int): e 值
	n (int): n 值
	primes (List[int]): 用于攻击的多素数列表
	powers (可选)(List[int]): 各素数对应的阶数，默认均为 1 次方

返回值：
	m (str): RSA 多素数攻击后得到的原文
```

<br>

`RSA_LowEncryptionIndex_Attack(c: int, e: int, n: int) -> str`：

```
用于对长整数形式的 RSA 密文进行低加密指数攻击并解出原文（尝试 10 万次累加 n 超过后会抛出异常）。

参数：
	c (int): 待进行低加密指数攻击的长整数形式的 RSA 密文
	e (int): e 值
	n (int): n 值

返回值：
	m (str): RSA 低加密指数攻击后得到的原文
```

<br>

`RSA_CommonMod_Attack(c1: int, c2: int, e1: int, e2: int, n: int) -> str`：

```
用于对长整数形式的 RSA 密文进行共模攻击并解出原文。

参数：
	c1 (int): 待进行共模攻击的长整数形式的第一串 RSA 密文
	c2 (int): 待进行共模攻击的长整数形式的第二串 RSA 密文
	e1 (int): c1 的 e 值
	e2 (int): c2 的 e 值
	n (int): n 值

返回值：
	m (str): RSA 共模攻击后得到的原文
```

<br>

`RSA_Broadcast_Attack(cs: list, e: int, ns: list) -> str`：

```
用于对长整数形式的 RSA 密文列表进行广播攻击并解出原文。

参数：
	cs (List[int]): 待进行广播攻击的长整数形式的 RSA 密文列表
	e (int): e 值
	ns (List[int]): 各密文对应的 n 值的列表

返回值：
	m (str): RSA 广播攻击后得到的原文
```

<br>

`RC4_Encrypt(Text: str, Key: str) -> str`：

```
用于对字符串进行 RC4 加密。

参数：
	Text (str): 待进行 RC4 加密的字符串
	Key (str): 加密密钥

返回值：
	EncryptedText (str): RC4 加密后得到的密文（ Base64 编码形式）
```

<br>

`RC4_Decrypt(Text: str, Key: str) -> str`：

```
用于对 Base64 编码形式的 RC4 密文进行解密。

参数：
	Text (str): 待解密的 Base64 编码形式的 RC4 密文
	Key (str): 解密密钥

返回值：
	DecryptedText (str): RC4 解密后得到的原文
```

<br>

### ClassicalCryptoUtils 类

本模块用于解决古典密码学问题。

`Caesar_Encrypt(Text: str, Move: int = 3) -> str`：

```
用于对字符串进行 Caesar 加密。

参数：
	Text (str): 待进行 Caesar 加密的字符串
	Move (int): 移位位数，默认为 3

返回值：
	EncryptedText (str): Caesar 加密后得到的密文
```

<br>

`Caesar_Decrypt(Text: str, Move: int = 3) -> str`：

```
用于对 Caesar 密文进行解密。

参数：
	Text (str): 待进行解密的 Caesar 密文
	Move (int): 移位位数，默认为 3

返回值：
	DecryptedText (str): Caesar 解密后得到的原文
```

<br>

`Caesar_Attack(Text: str) -> list`：

```
用于对 Caesar 密文进行爆破攻击。

参数：
	Text (str): 待进行爆破攻击的 Caesar 密文

返回值：
	Result (List[str]): Caesar 爆破攻击后得到的字符串列表
```

<br>

`Morse_Encrypt(Text: str) -> str`：

```
用于对字符串进行 Morse 加密。

参数：
	Text (str): 待进行 Morse 加密的字符串

返回值：
	EncryptedText (str): Morse 加密后得到的密文（未找到映射关系的字符将保持不变）
```

<br>

`Morse_Decrypt(Text: str) -> str`：

```
用于对 Morse 密文进行解密。

参数：
	Text (str): 待进行解密的 Morse 密文（以'/'进行分隔）

返回值：
	DecryptedText (str): Morse 解密后得到的原文（未找到映射关系的字符将保持不变）
```

<br>

`Bacon_Encrypt(Text: str) -> str`：

```
用于对字符串进行 Bacon 加密。

参数：
	Text (str): 待进行 Bacon 加密的字符串

返回值：
	EncryptedText (str): Bacon 加密后得到的密文（大写形式 未找到映射关系的字符将以[]包裹）
```

<br>

`Bacon_Decrypt(Text: str) -> str`：

```
用于对 Bacon 密文进行解密。

参数：
	Text (str): 待进行解密的 Bacon 密文

返回值：
	DecryptedText (str): Bacon 解密后得到的原文（大写形式 未找到映射关系的字符将以[]包裹）
```

<br>

`Fence_Encrypt(Text: str, Fence: int) -> str`：

```
用于对字符串进行 Fence 加密。

参数：
	Text (str): 待进行 Fence 加密的字符串
	Fence (int): 栏数

返回值：
	EncryptedText (str): Fence 加密后得到的密文
```

<br>

`Fence_Decrypt(Text: str, Fence: int) -> str`：

```
用于对 Fence 密文进行解密。

参数：
	Text (str): 待进行解密的 Fence 密文
	Fence (int): 栏数

返回值：
	DecryptedText (str): Fence 解密后得到的原文
```

<br>

`Fence_Attack(Text: str) -> list`：

```
用于对 Fence 密文进行爆破攻击。

参数：
	Text (str): 待进行爆破攻击的 Fence 密文

返回值：
	Result (List[tuple]): Fence 爆破攻击后得到的元组列表（字符串, 栏数）
```

<br>

`WFence_Encrypt(Text: str, Fence: int) -> str`：

```
用于对字符串进行 WFence 加密。

参数：
	Text (str): 待进行 WFence 加密的字符串
	Fence (int): 栏数

返回值：
	EncryptedText (str): WFence 加密后得到的密文
```

<br>

`WFence_Decrypt(Text: str, Fence: int) -> str`：

```
用于对 WFence 密文进行解密。

参数：
	Text (str): 待进行解密的 WFence 密文
	Fence (int): 栏数

返回值：
	DecryptedText (str): WFence 解密后得到的原文
```

<br>

`WFence_Attack(Text: str) -> list`：

```
用于对 WFence 密文进行爆破攻击。

参数：
	Text (str): 待进行爆破攻击的 WFence 密文

返回值：
	Result (List[tuple]): WFence 爆破攻击后得到的元组列表（字符串, 栏数）
```

<br>

### MiscUtils 类

本模块用于处理进制转换和常用哈希。

`Binary_String(Binary: str) -> str`：

```
用于将形如"1010...0101"的二进制字符串按照"8位1字符"的规则转换为字符串。

参数：
	Binary (str): 二进制字符串

返回值：
	String (str): 转换得到的字符串
```

<br>

`Binary_Dec(Binary: str) -> int`：

```
用于将形如"1010...0101"的二进制字符串转换为十进制整数形式。

参数：
	Binary (str): 二进制字符串

返回值：
	Dec (int): 转换得到的十进制整数
```

<br>

`Binary_Hex(Binary: str) -> str`：

```
用于将形如"1010...0101"的二进制字符串转换为十六进制字符串形式（含 0x 前缀）。

参数：
	Binary (str): 二进制字符串

返回值：
	Hex (str): 转换得到的十六进制字符串
```

<br>

`Dec_String(Dec: int) -> str`：

```
用于将十进制整数转换为字符串（UTF-8 字符集）。

参数：
	Dec (int): 十进制整数

返回值：
	String (str): 转换得到的字符串
```

<br>

`Dec_Binary(Dec: int) -> str`：

```
用于将十进制整数转换为二进制字符串形式（含 0b 前缀）。

参数：
	Dec (int): 十进制整数

返回值：
	Binary (str): 转换得到的二进制字符串
```

<br>

`Dec_Hex(Dec: int) -> str`：

```
用于将十进制整数转换为十六进制字符串形式（含 0x 前缀）。

参数：
	Dec (int): 十进制整数

返回值：
	Hex (str): 转换得到的十六进制字符串
```

<br>

`Hex_String(Hex: str) -> str`：

```
用于将形如"0a0b0c...1c1b1a"的十六进制字符串按照"2位1字符"的规则转换为字符串。

参数：
	Hex (str): 十六进制字符串

返回值：
	String (str): 转换得到的字符串
```

<br>

`Hex_Binary(Hex: str) -> str`：

```
用于将形如"0a0b0c...1c1b1a"的十六进制字符串为二进制字符串形式（含 0b 前缀）。

参数：
	Hex (str): 十六进制字符串

返回值：
	Binary (str): 转换得到的二进制字符串
```

<br>

`Hex_Dec(Hex: str) -> int`：

```
用于将形如"0a0b0c...1c1b1a"的十六进制字符串为十进制整数形式。

参数：
	Hex (str): 十六进制字符串

返回值：
	Dec (int): 转换得到的十进制整数
```

<br>

`SHA1(Text: str) -> str`：

```
用于获取字符串的 SHA1 哈希值。

参数：
	Text (str): 字符串

返回值：
	Hash (str): 该字符串的 SHA1 哈希值（十六进制字符串，不含 0x 前缀）
```

<br>

`SHA256(Text: str) -> str`：

```
用于获取字符串的 SHA256 哈希值。

参数：
	Text (str): 字符串

返回值：
	Hash (str): 该字符串的 SHA256 哈希值（十六进制字符串，不含 0x 前缀）
```

<br>

`SHA512(Text: str) -> str`：

```
用于获取字符串的 SHA512 哈希值。

参数：
	Text (str): 字符串

返回值：
	Hash (str): 该字符串的 SHA512 哈希值（十六进制字符串，不含 0x 前缀）
```

<br>

`MD5(Text: str) -> str`：

```
用于获取字符串的 MD5 哈希值。

参数：
	Text (str): 字符串

返回值：
	Hash (str): 该字符串的 MD5 哈希值（十六进制字符串，不含 0x 前缀）
```

<br>

## PoW 模块

本模块用于解决连接题目环境时可能遇到的工作量证明问题，在 Linux 环境下可以正常运行。

```python
from Poseidon.PoW import PoWUtils
```

### PoWUtils 类

`ProofOfWork_SHA256_Full(Url: str, Port: int, HashBegin: str, HashEnd: str, TextLength: int, SendAfter: str) -> remote`：

```
用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了 SHA256 的完整值，求长度为参数 (TextLength:int) 的字符串使得其 SHA256 值与给出的 SHA256 值相等。

参数：
	Url (str): 题目环境的链接地址
	Port (int): 题目环境的端口号
	HashBegin (str): 哈希值之前的字符串
	HashEnd (str): 哈希值之后的字符串
	TextLength (int): 待求解的字符串的长度
	SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

返回值：
	Connection (pwn.remote): 与服务器建立的连接对象
```

<br>

`ProofOfWork_SHA256_Prefix(Url: str, Port: int, PrefixBegin: str, PrefixEnd: str, PrefixLength: int, MaxTextLength: int, SendAfter: str) -> remote`：

```
用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了 SHA256 的前缀值，求一个最大长度不超过参数 (MaxTextLength:int) 的字符串使得其 SHA256 值的前缀与给出的 SHA256 前缀相等。

参数：
	Url (str): 题目环境的链接地址
	Port (int): 题目环境的端口号
	PrefixBegin (str): 哈希值前缀之前的字符串
	PrefixEnd (str): 哈希值前缀之后的字符串
	PrefixLength (int): 哈希值前缀的字符串的长度
	MaxTextLength (int): 待求解的字符串的最大长度
	SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

返回值：
	Connection (pwn.remote): 与服务器建立的连接对象
```

<br>

`ProofOfWork_SHA256_EndWithZero(Url: str, Port: int, KnownBegin: str, KnownEnd: str, UnknownLength: int, EndWithZeroLength: int, SendAfter: str) -> remote`：

```
用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了原文的前一部分，剩下长度（UnknownLength:int）的部分未知，要求解出未知部分的字符串，以使得与已知部分拼接得到的字符串的 SHA256 值的二进制形式中末尾所包含的 0 的个数为（EndWithZeroLength:int）。

参数：
	Url (str): 题目环境的链接地址
	Port (int): 题目环境的端口号
	KnownBegin (str): 已知部分之前的字符串
	KnownEnd (str): 已知部分之后的字符串
	UnknownLength (int): 未知部分的字符串的长度
	EndWithZeroLength (int): SHA256 值的二进制形式中末尾所包含的 0 的个数
	SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

返回值：
	Connection (pwn.remote): 与服务器建立的连接对象
```

<br>

`ProofOfWork_MD5_Full(Url: str, Port: int, HashBegin: str, HashEnd: str, TextLength: int, SendAfter: str) -> remote`：

```
用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了 MD5 的完整值，求长度为参数 (TextLength:int) 的字符串使得其 MD5 值与给出的 MD5 值相等。

参数：
	Url (str): 题目环境的链接地址
	Port (int): 题目环境的端口号
	HashBegin (str): 哈希值之前的字符串
	HashEnd (str): 哈希值之后的字符串
	TextLength (int): 待求解的字符串的长度
	SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

返回值：
	Connection (pwn.remote): 与服务器建立的连接对象
```

<br>

`ProofOfWork_MD5_Prefix(Url: str, Port: int, PrefixBegin: str, PrefixEnd: str, PrefixLength: int, MaxTextLength: int, SendAfter: str) -> remote`：

```
用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了 MD5 的前缀值，求一个最大长度不超过参数 (MaxTextLength:int) 的字符串使得其 MD5 值的前缀与给出的 MD5 前缀相等。

参数：
	Url (str): 题目环境的链接地址
	Port (int): 题目环境的端口号
	PrefixBegin (str): 哈希值前缀之前的字符串
	PrefixEnd (str): 哈希值前缀之后的字符串
	PrefixLength (int): 哈希值前缀的字符串的长度
	MaxTextLength (int): 待求解的字符串的最大长度
	SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

返回值：
	Connection (pwn.remote): 与服务器建立的连接对象
```

<br>

`ProofOfWork_MD5_EndWithZero(Url: str, Port: int, KnownBegin: str, KnownEnd: str, UnknownLength: int, EndWithZeroLength: int, SendAfter: str) -> remote`：

```
用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了原文的前一部分，剩下长度（UnknownLength:int）的部分未知，要求解出未知部分的字符串，以使得与已知部分拼接得到的字符串的 MD5 值的二进制形式中末尾所包含的 0 的个数为（EndWithZeroLength:int）。

参数：
	Url (str): 题目环境的链接地址
	Port (int): 题目环境的端口号
	KnownBegin (str): 已知部分之前的字符串
	KnownEnd (str): 已知部分之后的字符串
	UnknownLength (int): 未知部分的字符串的长度
	EndWithZeroLength (int): MD5 值的二进制形式中末尾所包含的 0 的个数
	SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

返回值：
	Connection (pwn.remote): 与服务器建立的连接对象
```

<br>

# 开源许可

本项目使用 [GPL-3.0](https://choosealicense.com/licenses/gpl-3.0/) 作为开源许可证。
