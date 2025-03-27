<div align="center">

[![data](https://socialify.git.ci/B1ue1nWh1te/Poseidon/image?font=Bitter&forks=1&issues=1&language=1&logo=https%3A%2F%2Fimg.seaeye.cn%2Fimg%2Fposeidon%2Flogo.png&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Auto)](https://github.com/B1ue1nWh1te/Poseidon)

**Poseidon 海神波塞冬**，本工具库对常用的链上交互操作进行了模块化抽象与简洁式封装，

让开发者能够轻松快速地与主流区块链网络进行交互。目前支持任意 EVM 链。

[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)
[![Python](https://img.shields.io/badge/python-3.9+-blue)](https://www.python.org/)
[![Release](https://img.shields.io/github/v/release/B1ue1nWh1te/Poseidon)](https://github.com/B1ue1nWh1te/Poseidon/releases/)
[![Downloads](https://img.shields.io/pypi/dm/poseidon-python?color=%23008BE1)](https://pypi.org/project/poseidon-python/)

</div>

# 安装

## 最简方式

直接使用 pip 安装，但有可能由于本地 python 环境依赖库紊乱而导致脚本运行出错。

```bash
pip install -U poseidon-python
```

## 推荐方式

基于 [模板库](https://github.com/B1ue1nWh1te/PoseidonTemplate) 使用 poetry 创建虚拟环境，这样可以保证脚本运行环境干净，减少出现意外错误的可能。

安装 poetry 虚拟环境管理工具（如果之前未安装）：

```bash
pip install -U poetry
```

克隆 [模板库](https://github.com/B1ue1nWh1te/PoseidonTemplate) 至本地（也可先使用该模板库创建一个副本至你自己的 Github 仓库中再克隆）：

```bash
git clone git@github.com:B1ue1nWh1te/PoseidonTemplate.git
```

切换至模板仓库目录并安装虚拟环境：

```bash
cd PoseidonTemplate
poetry install
```

之后假设你编写了一个名为 main.py 的脚本要运行：

```bash
poetry shell
python main.py
```

# 示例

- [测试样例](https://github.com/B1ue1nWh1te/Poseidon/tree/main/tests)

- [模板库](https://github.com/B1ue1nWh1te/PoseidonTemplate)

以下通过对比 Poseidon 与 web3.py 的使用，展示 Poseidon 的简洁性优势。

## 使用 Poseidon

```python
from poseidon.evm import Chain, Account, Contract, Utils

rpc_url = "https://<RPC_URL>"
chain = Chain(rpc_url)

address, private_key = Utils.generate_new_account()
account = Account(chain, private_key)
signature_data = account.sign_message_string("test")
signed_message_data = Utils.recover_message_string("test", signature_data.signature_data.signature)
account.send_transaction(to=ZERO_ADDRESS, data="0x", value=1)

Utils.set_solidity_version("0.8.28")
abi, bytecode = Utils.compile_solidity_contract("./Contract.sol", "Contract")
tx_receipt = account.deploy_contract(abi, bytecode)

contract: Contract = tx_receipt.contract
contract.call_function("anyWriteFunction", "(param1)", "(param2)")
contract.read_only_call_function("anyReadOnlyFunction", "(param1)", "(param2)")
```

## 使用 web3.py

```python
from web3 import Web3
from eth_account import Account as Web3Account
from eth_account.messages import encode_defunct
from solcx import compile_source, install_solc
import json

w3 = Web3(Web3.HTTPProvider("https://<RPC_URL>"))

account = Web3Account.create()
address = account.address
private_key = account.key.hex()
message = encode_defunct(text="test")
signed_message = w3.eth.account.sign_message(message, private_key=private_key)
recovered_address = w3.eth.account.recover_message(message, signature=signed_message.signature)
transaction = {
    'nonce': w3.eth.get_transaction_count(address),
    'to': ZERO_ADDRESS,
    'value': 1,
    'gas': 21000,
    'gasPrice': w3.eth.gas_price,
    'data': '0x'
}
signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

install_solc('0.8.28')
with open('./Contract.sol', 'r') as file:
    source = file.read()
compiled_sol = compile_source(source)
contract_interface = compiled_sol['<stdin>:Contract']
bytecode = contract_interface['bin']
abi = contract_interface['abi']
contract = w3.eth.contract(abi=abi, bytecode=bytecode)
transaction = contract.constructor().build_transaction({
    'from': address,
    'nonce': w3.eth.get_transaction_count(address),
    'gas': 2000000,
    'gasPrice': w3.eth.gas_price
})
signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

contract_instance = w3.eth.contract(address=tx_receipt.contractAddress, abi=abi)
write_txn = contract_instance.functions.anyWriteFunction("(param1)", "(param2)").build_transaction({
    'from': address,
    'nonce': w3.eth.get_transaction_count(address),
    'gas': 200000,
    'gasPrice': w3.eth.gas_price
})
signed_txn = w3.eth.account.sign_transaction(write_txn, private_key)
tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
result = contract_instance.functions.anyReadOnlyFunction("(param1)", "(param2)").call()
```

# 文档

主要文档：[**Poseidon Docs**](https://poseidon.seaeye.cn/)

其他文档：[**web3.py(v6) Docs**](https://web3py.readthedocs.io/en/v6.20.2/)

# 注意事项

1. **EVM** 模块的所有功能在 `Ethereum Sepolia`, `Arbitrum Sepolia`, `Optimism Sepolia`, `BSC Testnet`, `Polygon Amoy` **测试网络**中均正常通过测试。

2. 建议始终使用**全新生成的**账户进行导入，以避免意外情况下隐私数据泄露。

3. 关于安全性，代码完全开源并且基于常用的第三方库进行封装，可以自行进行审阅。

4. 如果你在使用过程中遇到了问题或者有任何好的想法和建议，欢迎提 [**Issues**](https://github.com/B1ue1nWh1te/Poseidon/issues) 或 [**PRs**](https://github.com/B1ue1nWh1te/Poseidon/pulls) 进行反馈和贡献。

5. 本工具库**开源的目的是进行技术开发上的交流与分享**，不涉及任何其他方面的内容。原则上该工具只应该在开发测试环境下与区块链测试网进行交互调试，作者并不提倡在其他情况下使用。若开发者自行选择在具有经济价值的区块链主网中使用，所造成的任何影响由其个人负责，与作者本人无关。

[![Star History Chart](https://api.star-history.com/svg?repos=B1ue1nWh1te/Poseidon&type=Date)](https://star-history.com/#B1ue1nWh1te/Poseidon&Date)
