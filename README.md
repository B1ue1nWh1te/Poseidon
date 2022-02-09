<div align="center">

# Poseidon

![data](https://socialify.git.ci/B1ue1nWh1te/Poseidon/image?description=1&font=Rokkitt&forks=1&issues=1&language=1&owner=1&pattern=Circuit%20Board&stargazers=1&theme=Dark)

海神波塞冬

一个也许有用的 CTF 工具

它会随着我技术水平的提升而不断更新

[![Lisence](https://img.shields.io/github/license/B1ue1nWh1te/Poseidon)](https://github.com/B1ue1nWh1te/Poseidon/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/B1ue1nWh1te/Poseidon?include_prereleases)](https://github.com/B1ue1nWh1te/Poseidon/releases/)
[![Python Version](https://img.shields.io/badge/python-3.7+-blue)](https://www.python.org/)
[![CTF](https://img.shields.io/badge/CTF-purple)](<https://en.wikipedia.org/wiki/Capture_the_flag_(cybersecurity)>)

</div>

# 前言

本工具仅适用于 CTF 比赛做题，请遵守信息安全相关的法律法规。

目前`海神波塞冬`含有四个模块，分别是`Blockchain`、`Crypto`、`Normal`、`Pwn`。

由于我个人研究方向的原因，其中`Blockchain`和`Crypto`这两个模块的功能较为全面，有较高的实用价值。而`Normal`和`Pwn`两个模块的功能是比较少的，以后会慢慢更新。

同时欢迎你与我一起共同完善这个项目，让它在未来能够真正成为像它的名字一般无比强大的存在，`海神波塞冬`。

# 开始使用

1.克隆本仓库

```bash
git clone https://github.com/B1ue1nWh1te/Poseidon
```

2.切换目录并安装依赖库

```bash
cd Poseidon

pip install -r requirements.txt
```

3.在脚本代码中导入需要的功能函数

例如：

```python
from Poseidon_Crypto import RSA_Wiener_Attack

c=95267370256066769838337747074613384873130229960498483863532367776035032572852929192615316576459694331250252556497631694740022138111036400986764177734369838342591998927562945381419058366186792509393106287586887362087306654669323671777947824036291661918607426035181203851539103325998426459243898101029020295691838189129620371008325930013559810102919311870290134826512484097220197539230546164153197998791243720942561991399617076030993626951506104013918049711672627654688980120970533645733673090635057413871984027810703923369437250893348483086782212034342653051281902817392018001479258420669264415501475932933992850728706672929405313600749215985411632608095628677993813597979403642429941499746829792989542997812081764690610483215261053538372608164787573234782242231516605578411379752580289336917041163266741855032601096072967110532711990529880332617370524270464075773759819395063442942936380266233365841095277630192476402511722171921606815101725111071300857694482840853229685558425271848066927242827086521317380782171238880746369706438528481816398259903146586949100039175077183726950898184647643394954945610710152392201403059197872874917090778829365677505140875737144660497677868022940399693688784730715842812161819984500346848776216553
e=173279456743230080621017365782109382300464407222659715088896977256836281616268680945198842762589774463979475671411325549491119275843634476767434141162251440128267743628520687819778054081862669392022638561711243048686177024706794109732879008036054980520978026668448968472856614200050693198639764864102357612979283854505926693806667493401447849840959699906591346529086698704432539620975330467442772776717445252023030122718721643653304047196807293575880524103499301481658959884059857143042853270421653019072455543805443412672623573727047140020884143266326560866330729394363196503593380265047467096543598311441458530310679485721108818417037058590314288658010217988281010512823896799300839815159157461324129606735170857765562003742951529657870330430909029521121213811802047749272088028568546720500024446323242611654413563293934152586519996153254714554351058322610356108612279003362680490053142204471044921591273897722773149804320291989000233468903056147470874130344913224325418672879543105264594005427832924916194805177326950999764303377811639278163209680026574862045662012789632391097789691415069932107136619935252148482058632893898927949072268406881309426626792830044382260515591176693471696319954446030667166309913114122104514824977979
n=470644710803932932512978827923303177251118147254197669197880877933691333373985617541803529915823866778893951837205409386851882681891901968039669086359788209984380028571953695488594409481787886910251596530765294590299041804794064683930600833830314491883013079189678180741236571163429381063099014246011795027346952166636867433910238423840581018902725192909630974449833401049616775405505215676016785334488391487465594571285890541811935855077283960590595117406699633923563526092192621628384206760218861223827563700801244930662858751794860059761679913658718964802644824629046733812979885743418624227999490303158082154081306362983892991361638394422732061859098104545472186525114696124448200241859164591512578048979001771751983587722958729782617339007332560114087497582935926352896360634917079289956976854666712751933808837805975693683147231224198994010014584453287020306301646174206473218894297633751493304464876906150106514614910587021672849754663941168328636325762572621857629768876059149757228346459502909392992682012429036971329109770800704396127807790510024881922916421853812648659345484677108899082003317583049300042120635991950435890529487703525501610733618101722310430775843942147829772926122874312839148564489983715775087153849089

print(RSA_Wiener_Attack(c,e,n))
```

运行结果：

```data
flag{Hello_World!-Respect_Poseidon's_Authority!}
```

# 现有功能

## Blockchain 模块

一般情况下，需要先初始化`Chain`，再初始化`Account`，才可正常使用全部功能。

### Chain 类

初始化 Chain 连接上一条私有链(由 geth 搭建)：

```python
from Poseidon_Blockchain import *

chain=Chain("http://localhost:8545")
```

展示链的基本信息-`Chain.ShowBasicInformation()`：输出`ClientVersion`、`ChainId`、`BlockNumber`、`PeerCount`

展示区块的基本信息-`Chain.ShowBlockInformation(BlockId)`：输出`BlockNumber`、`CoinBase`、`TransactionCount`、`TransactionHashs`、`ExtraData`、`ProofOfAuthorityData`、`TimeStamp`

展示交易的基本信息（通过交易哈希）-`Chain.ShowTransactionByHash(TransactionHash)`：输出`BlockNumber`、`TransactionIndex`、`From`、`To`、`InputData`、`Value`

展示交易的基本信息（通过区块和交易索引）-`Chain.ShowTransactionByBlockIdAndIndex(BlockId,TransactionId)`：输出`BlockNumber`、`TransactionIndex`、`From`、`To`、`InputData`、`Value`

获取某个账户的余额-`Chain.GetBalanceByAddress(Address)`：输出并返回`Balance`，单位为`wei`

获取某个合约的字节码-`Chain.GetCodeByAddress(Address)`：输出并返回`Bytecode`

获取某个合约的某个位置的存储-`Chain.GetStorage(Address,Index)`：输出并返回`Storage`

从下标零开始按数量读取某个合约的存储-`Chain.DumpStorage(Address,Count)`：输出并返回`Storage`，类型为`list`

### Account 类

创建新账户并初始化 Account 并连接至先前定义的链：

```python
......

account=Account(chain,Account.CreateNewAccount()[1])
```

获取自身余额-`Account.GetSelfBalance()`：输出并返回`Balance`，单位为`wei`。

发送交易-`Account.SendTransactionToChain(To,Data,Value, Gas)`：输出`Txn`、`TransactionHash`、`TransactionReceipt`，返回`TransactionReceipt`

部署合约-`Account.DeployContractToChain(Abi,Bytecode,Value)`：输出`Txn`、`TransactionHash`、`TransactionReceipt`、`ContractAddress`，返回`(ContractAddress, Contract)`

创建新账户-`Account.CreateNewAccount()`：输出并返回`(Address, PrivateKey)`

### 其他

将 solidity 合约代码编译成 abi 和 bytecode-`SolidityToAbiAndBytecode(Course,ContractName)`：输出、返回并保存`(Abi, Bytecode)`

### 做题的基本模板

'''python
from Poseidon_Blockchain import \*
from loguru import logger
import solcx

#安装指定版本的 solidity
SolidityVersion = solcx.install_solc('')
solcx.set_solc_version(SolidityVersion)
logger.log(f"Solidity Version:{SolidityVersion}")

#连接私链的 RPC 使用私钥生成账户
chain = Chain("")
account = Account(chain, "0x")
contractAddress = Web3.toChecksumAddress("")

#编译合约代码
abi, bytecode = SolidityToAbiAndBytecode(".sol", "")
contract = chain.Net.eth.contract(address=contractAddress, abi=abi)

#调用合约函数并发出交易
transactionData = contract.functions.functionName(params).buildTransaction()
transactionReceipt = account.SendTransactionToChain(transactionData["to"], transactionData["data"])

#将要调用的函数进行编码
arg1 = contract.encodeABI(fn_name="functionName")
arg2 = contract.encodeABI(fn_name="functionName", args=[arg1])
transactionData = contract.functions.functionName(arg1, arg2).buildTransaction({'value': 0})
transactionReceipt = account.SendTransactionToChain(transactionData["to"], transactionData["data"], transactionData["value"])

logger.success("Execution completed.")
'''

## Crypto 模块

```python
from Poseidon_Crypto import *
```

目前支持：

`Base64编码解码及解隐写`、`Base32编码解码`、`Base16编码解码`、`十二宫密码-解密`、`云影密码-解密`、`摩斯密码-加解密`、`培根密码-加解密`、`维吉尼亚密码-加解密`、`凯撒密码-加解密及爆破攻击`、`仿射密码-加解密及爆破攻击`、`栅栏密码-加解密及爆破攻击`、`W型栅栏密码-加解密及爆破攻击`、`RC4密码-加解密`、`AES密码-加解密`、`RSA密码-加解密及攻击(低解密指数攻击、低加密指数攻击、广播攻击、共模攻击、多素数加密攻击)`

## Normal 模块

```python
from Poseidon_Normal import *
```

目前支持：

`二进制转字符串、十进制、十六进制`、`十进制转字符串、二进制、十六进制`、`十六进制转字符串、二进制、十进制`、`以字节形式输出某个文件`、`文本的SHA1、SHA256、SHA512、MD5`、`PNG文件的CRC爆破`、`01串绘制为二维码`、`RGB串绘制为图像`、`图像转为RGB串`、`简易封装的request请求函数`

## Pwn 模块

```python
from Poseidon_Pwn import *
```

目前支持：

`SHA256工作量证明`、`MD5工作量证明`，按哈希前缀或整串哈希来爆破出符合的字符串，并自动提交以便激活答题环境。

# 开源许可

本项目使用 [GPL-3.0](https://choosealicense.com/licenses/gpl-3.0/) 作为开源许可证。
