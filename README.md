<div align="center">

# Poseidon

![data](https://socialify.git.ci/B1ue1nWh1te/Poseidon/image?description=1&font=Rokkitt&forks=1&issues=1&language=1&owner=1&pattern=Circuit%20Board&stargazers=1&theme=Dark)

海神波塞冬 Poseidon，CTF 解题快速利用工具，是攻克 Blockchain 方向的得力助手，也包含一些 Crypto 和 Misc 方向的小功能，可用于快速编写解题脚本而无需繁琐的步骤。

[![Lisence](https://img.shields.io/github/license/B1ue1nWh1te/Poseidon)](https://github.com/B1ue1nWh1te/Poseidon/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/B1ue1nWh1te/Poseidon?include_prereleases)](https://github.com/B1ue1nWh1te/Poseidon/releases/)
[![Python Version](https://img.shields.io/badge/python-3.7+-blue)](https://www.python.org/)
[![CTF](https://img.shields.io/badge/CTF-purple)](<https://en.wikipedia.org/wiki/Capture_the_flag_(cybersecurity)>)
[![Visitors](https://visitor-badge.glitch.me/badge?page_id=B1ue1nWh1te-Poseidon&left_color=gray&right_color=orange)](https://github.com/B1ue1nWh1te/Poseidon)

</div>

# 注意事项

本工具仅可用于 CTF 比赛解题，请勿作其他用途。

# 安装

```bash
pip install poseidon-python
```

# 现有功能

## Blockchain 模块

一般情况下，需要先创建`Chain`实例，再创建`Account`实例，之后就可以使用该账户发送交易到指定链上了，如果需要用到合约，还需要创建`Contract`实例，才可对合约函数进行调用。

例如[Ethernaut-Coin Flip](https://ethernaut.openzeppelin.com/level/0x4dF32584890A0026e56f7535d0f2C6486753624f)的[解题脚本](https://www.seaeye.cn/archives/468.html)：

```python
from Poseidon.Blockchain import *
from loguru import logger
import time

# 日志
logger.add('CoinFlip_{time}.log')

# 配置Solidity版本
BlockchainUtils.SwitchSolidityVersion("0.8.0")

# 连接至链
chain = Chain("https://rinkeby.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161")

# 使用私钥导入账户
account = Account(chain, "<Your Private Key>")

# 题目合约地址规范化
exerciseContractAddress = Web3.toChecksumAddress("<Exercise Contract Address>")

# 编译题目合约
abi, bytecode = BlockchainUtils.Compile("CoinFlip.sol", "CoinFlip")

# 实例化题目合约
exerciseContract = Contract(account, exerciseContractAddress, abi)

# 编译攻击合约
abi, bytecode = BlockchainUtils.Compile("Hacker.sol", "Hacker")

# 部署攻击合约
data = account.DeployContract(abi, bytecode)
hackerAddress, hacker = data["ContractAddress"], data["Contract"]

# 调用十次攻击合约
i = 0
while i < 10:
    try:
        temp = hacker.CallFunction(0,"hack", exerciseContractAddress)
        if temp[1] != 0:
            i += 1
    except:
        print("[Error]Waiting for next block.")
        time.sleep(5)

# 获取题目解出状态
exerciseContract.ReadOnlyCallFunction("consecutiveWins")

logger.success("Execution completed.")
```

### Chain

`__init__(self, RPCUrl: str, RequestParams: dict = None)`: 初始化链

`GetBasicInformation(self) -> dict`: 获取链基本信息

`GetBlockInformation(self, BlockID="latest") -> dict`: 根据块 ID 获取指定块的信息

`GetTransactionByHash(self, TransactionHash: str) -> dict`: 根据哈希获取指定交易的信息

`GetTransactionByBlockIdAndIndex(self, BlockID, TransactionIndex: int) -> dict`: 根据交易所在块的 ID 与交易在该块中的索引获取指定交易的信息

`GetBalance(self, Address: str) -> int`: 获取指定地址的链原生代币余额

`GetCode(self, Address: str) -> str`: 获取指定地址的 Code

`GetStorage(self, Address: str, Index: int) -> str`: 根据索引获取指定地址的存储

`DumpStorage(self, Address: str, Count: int) -> list`: 从 0 开始依次读出指定地址的 Count 个存储槽数据

### Account

`__init__(self, Chain: Chain, PrivateKey: str)`：初始化账户

`GetSelfBalance(self) -> int`: 获取账户自身的链原生代币余额

`SendTransaction(self, To: str, Data: str, Value: int = 0, Gas: int = 10000000) -> dict`: 发送交易

`SendTransactionByEIP1559(self, To: str, Data: str, Value: int = 0, Gas: int = 1000000) -> dict`: 以 EIP-1559 形式发送交易

`DeployContract(self, ABI: dict, Bytecode: str, Value: int = 0, *Arguments) -> dict`: 部署合约

`DeployContractByEIP1559(self, ABI: dict, Bytecode: str, Value: int = 0, *Arguments) -> dict`: 以 EIP-1559 形式部署合约

`SignMessage(self, Message: str) -> dict`: 对消息进行签名

### Contract

`__init__(self, Account: Account, Address: str, ABI: dict)`: 初始化合约

`CallFunction(self, Value: int, FunctionName: str, *FunctionArguments) -> dict`: 调用合约函数

`CallFunctionByEIP1559(self, Value: int, FunctionName: str, *FunctionArguments) -> dict`: 以 EIP-1559 形式调用合约函数

`ReadOnlyCallFunction(self, FunctionName: str, *FunctionArguments)`: 调用合约的只读函数

`EncodeABI(self, FunctionName: str, *FunctionArguments) -> str`: 编码调用 ABI

### BlockchainUtils

`SwitchSolidityVersion(SolidityVersion: str)`: 指定 Solidity 版本

`Compile(FileCourse: str, ContractName: str, AllowPaths: str = None) -> tuple`: 编译合约

`CreateNewAccount() -> tuple`: 创建新账户

`RecoverMessage(Message: str, Signature: str) -> str`: 复原被签名的消息

`RecoverMessageByHash(MessageHash: str, Signature: str) -> str`: 根据哈希复原被签名的消息

## Cryptography 模块

例如 RSA 密码的维纳攻击：

```python
from Poseidon.Cryptography import *

c=95267370256066769838337747074613384873130229960498483863532367776035032572852929192615316576459694331250252556497631694740022138111036400986764177734369838342591998927562945381419058366186792509393106287586887362087306654669323671777947824036291661918607426035181203851539103325998426459243898101029020295691838189129620371008325930013559810102919311870290134826512484097220197539230546164153197998791243720942561991399617076030993626951506104013918049711672627654688980120970533645733673090635057413871984027810703923369437250893348483086782212034342653051281902817392018001479258420669264415501475932933992850728706672929405313600749215985411632608095628677993813597979403642429941499746829792989542997812081764690610483215261053538372608164787573234782242231516605578411379752580289336917041163266741855032601096072967110532711990529880332617370524270464075773759819395063442942936380266233365841095277630192476402511722171921606815101725111071300857694482840853229685558425271848066927242827086521317380782171238880746369706438528481816398259903146586949100039175077183726950898184647643394954945610710152392201403059197872874917090778829365677505140875737144660497677868022940399693688784730715842812161819984500346848776216553
e=173279456743230080621017365782109382300464407222659715088896977256836281616268680945198842762589774463979475671411325549491119275843634476767434141162251440128267743628520687819778054081862669392022638561711243048686177024706794109732879008036054980520978026668448968472856614200050693198639764864102357612979283854505926693806667493401447849840959699906591346529086698704432539620975330467442772776717445252023030122718721643653304047196807293575880524103499301481658959884059857143042853270421653019072455543805443412672623573727047140020884143266326560866330729394363196503593380265047467096543598311441458530310679485721108818417037058590314288658010217988281010512823896799300839815159157461324129606735170857765562003742951529657870330430909029521121213811802047749272088028568546720500024446323242611654413563293934152586519996153254714554351058322610356108612279003362680490053142204471044921591273897722773149804320291989000233468903056147470874130344913224325418672879543105264594005427832924916194805177326950999764303377811639278163209680026574862045662012789632391097789691415069932107136619935252148482058632893898927949072268406881309426626792830044382260515591176693471696319954446030667166309913114122104514824977979
n=470644710803932932512978827923303177251118147254197669197880877933691333373985617541803529915823866778893951837205409386851882681891901968039669086359788209984380028571953695488594409481787886910251596530765294590299041804794064683930600833830314491883013079189678180741236571163429381063099014246011795027346952166636867433910238423840581018902725192909630974449833401049616775405505215676016785334488391487465594571285890541811935855077283960590595117406699633923563526092192621628384206760218861223827563700801244930662858751794860059761679913658718964802644824629046733812979885743418624227999490303158082154081306362983892991361638394422732061859098104545472186525114696124448200241859164591512578048979001771751983587722958729782617339007332560114087497582935926352896360634917079289956976854666712751933808837805975693683147231224198994010014584453287020306301646174206473218894297633751493304464876906150106514614910587021672849754663941168328636325762572621857629768876059149757228346459502909392992682012429036971329109770800704396127807790510024881922916421853812648659345484677108899082003317583049300042120635991950435890529487703525501610733618101722310430775843942147829772926122874312839148564489983715775087153849089

print(ModernCryptoUtils.RSA_Wiener_Attack(c,e,n))
```

运行结果：

```log
flag{Hello_World!-Respect_Poseidon's_Authority!}
```

### ModernCryptoUtils

`Base64_Encrypt(Text: str) -> str`: Base64 编码

`Base64_Decrypt(Text: str) -> str`: Base64 解码

`Base64_Stego_Decrypt(Base64List: list) -> str`: Base64 隐写破解

`Base32_Encrypt(Text: str) -> str`: Base32 编码

`Base32_Decrypt(Text: str) -> str`: Base32 解码

`Base16_Encrypt(Text: str) -> str`: Base16 编码

`Base16_Decrypt(Text: str) -> str`: Base16 解码

`AES_Encrypt(Text: str, Key: str, Mode=aes.MODE_ECB) -> str`: AES 加密

`AES_Decrypt(Text: str, Key: str, Mode=aes.MODE_ECB) -> str`: AES 解密

`RSA_Encrypt(Text: str, p: int, q: int, e: int) -> str`: RSA 加密

`RSA_Base64_Decrypt(Base64: str, p: int, q: int, e: int) -> str`: Base64 形式的 RSA 解密

`RSA_Long_Decrypt(Long: int, p: int, q: int, e: int) -> str`: 长整型形式的 RSA 解密

`RSA_Wiener_Attack(c: int, e: int, n: int) -> str`: RSA 维纳攻击

`RSA_MultiPrime_Attack(c: int, e: int, n: int, primes: list, powers: list = None) -> str`: RSA 多素数攻击

`RSA_LowEncryptionIndex_Attack(c: int, e: int, n: int) -> str`: RSA 低加密指数攻击

`RSA_CommonMod_Attack(c1: int, c2: int, e1: int, e2: int, n: int) -> str`: RSA 共模攻击

`RSA_Broadcast_Attack(cs: list, e: int, ns: list) -> str`: RSA 广播攻击

`RC4_Encrypt(Text: str, Key: str) -> str`: RC4 加密

`RC4_Decrypt(Text: str, Key: str) -> str`: RC4 解密

### ClassicalCryptoUtils

`Caesar_Encrypt(Text: str, Move: int = 3) -> str`: 恺撒加密

`Caesar_Decrypt(Text: str, Move: int = 3) -> str`: 恺撒解密

`Caesar_Attack(Text: str) -> list`: 恺撒攻击

`Morse_Encrypt(Morse: str) -> str`: 摩斯加密

`Morse_Decrypt(Morse: str) -> str`: 摩斯解密

`Bacon_Encrypt(Bacon: str) -> str`: 培根加密

`Bacon_Decrypt(Bacon: str) -> str`: 培根解密

`Vigenere_Encrypt(Text: str, Key: str) -> str`: 维吉尼亚加密

`Vigenere_Decrypt(Text: str, Key: str) -> str`: 维吉尼亚解密

`Fence_Encrypt(Text: str, Fence: int) -> str`: 栅栏加密

`Fence_Decrypt(Text: str, Fence: int) -> str`: 栅栏解密

`Fence_Attack(Text: str) -> list`: 栅栏攻击

`WFence_Encrypt(Text: str, Fence: int) -> str`: W 型栅栏加密

`WFence_Decrypt(Text: str, Fence: int) -> str`: W 型栅栏解密

`WFence_Attack(Text: str) -> list`: W 型栅栏攻击

`Affine_Encrypt(Text: str, a: int, b: int) -> str`: 仿射加密

`Affine_Decrypt(Text: str, a: int, b: int) -> str`: 仿射解密

`Affine_Attack(Text: str) -> list`: 仿射攻击

`Zodiac(Text: str, Foot: int) -> str`: 十二宫解密

`Yunying(Text: str) -> str`: 云影解密

## Misc 模块

```python
from Poseidon.Misc import *
```

### MiscUtils

`Binary_String(Binary: str) -> str`: 二进制转字符串

`Binary_Dec(Binary: str) -> str`: 二进制转十进制

`Binary_Hex(Binary: str) -> str`: 二进制转十六进制

`Dec_String(Dec: int) -> str`: 十进制转字符串

`Dec_Binary(Dec: int) -> bytes`: 十进制转二进制

`Dec_Hex(Dec: int) -> str`: 十进制转十六进制

`Hex_String(Hex: str) -> str`: 十六进制转字符串

`Hex_Binary(Hex: str) -> bytes`: 十六进制转二进制

`Hex_Dec(Hex: str) -> str`: 十六进制转十进制

`SHA1(Text: str) -> str`: SHA1

`SHA256(Text: str) -> str`: SHA256

`SHA512(Text: str) -> str`: SHA512

`MD5(Text: str) -> str`: MD5

### MiscAdvancedUtils

`CRC_Burst(Course: str) -> None`: PNG 图片的 CRC 爆破

`BinaryToQRCode(BinaryList: list) -> None`: 根据二进制列表数据绘出二维码

`RGBToImage(RGBList: list, X: int, Y: int, Mode: str = "Column") -> None`: 根据 RGB 列表数据绘出图片

`ImageToRGB(ImageCourse: str, Mode="Column") -> list`: 根据图片得出 RGB 列表数据

`Request(Url: str, Method: str = "GET", Headers: dict = None, Params: dict = None, Data: dict = None) -> dict`: 对 request 请求操作的封装

## PoW 模块

```python
from Poseidon.PoW import *
```

### PoWUtils

`ProofOfWork_SHA256_Full(Url: str, Port: int, Length: int, HashBegin: str, SendAfter: str) -> remote`: 已知 SHA256 的全部内容，求解原文

`ProofOfWork_SHA256_Prefix(Url: str, Port: int, PrefixLength: int, HashBegin: str, SendAfter: str) -> remote`: 已知 SHA256 的前缀，求解 SHA256 前缀相同的字符串

`ProofOfWork_MD5_Full(Url: str, Port: int, Length: int, HashBegin: str, SendAfter: str) -> remote`: 已知 MD5 的全部内容，求解原文

`ProofOfWork_MD5_Prefix(Url: str, Port: int, PrefixLength: int, HashBegin: str, SendAfter: str) -> remote`: 已知 MD5 的前缀，求解 MD5 前缀相同的字符串

# 开源许可

本项目使用 [GPL-3.0](https://choosealicense.com/licenses/gpl-3.0/) 作为开源许可证。
