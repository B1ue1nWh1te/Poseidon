<div align="center">

[![data](https://socialify.git.ci/B1ue1nWh1te/Poseidon/image?font=Bitter&forks=1&issues=1&language=1&logo=https%3A%2F%2Fimg.seaeye.cn%2Fimg%2Fposeidon%2Flogo.svg&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Auto)](https://github.com/B1ue1nWh1te/Poseidon)

**Poseidon 海神波塞冬**，本工具库对常用的链上交互操作进行了模块化抽象与简洁式封装，

让开发者能够轻松快速地与主流区块链网络进行交互。目前支持任意 EVM 链。

[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)
[![Python](https://img.shields.io/badge/python-3.9+-blue)](https://www.python.org/)
[![Release](https://img.shields.io/github/v/release/B1ue1nWh1te/Poseidon)](https://github.com/B1ue1nWh1te/Poseidon/releases/)
[![Downloads](https://img.shields.io/pypi/dm/poseidon-python)](https://pypi.org/project/poseidon-python/)

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

# 文档

[**Poseidon Docs**](https://seaverse.gitbook.io/poseidon)

# 注意事项

1. **EVM** 模块的所有功能在 `Ethereum Sepolia, Arbitrum Sepolia, Optimism Sepolia, BSC Testnet, Polygon PoS Amoy` **测试网络**中均正常通过测试。

2. 建议始终使用**全新生成的**账户进行导入，以避免意外情况下隐私数据泄露。

3. 关于安全性，代码完全开源并且基于常用的第三方库进行封装，可以自行进行审阅。

4. 如果你在使用过程中遇到了问题或者有任何好的想法和建议，欢迎提 [**Issues**](https://github.com/B1ue1nWh1te/Poseidon/issues) **或** [**PR**](https://github.com/B1ue1nWh1te/Poseidon/pulls) 进行反馈和贡献。

5. 本工具库**开源的目的是进行技术开发上的交流与分享**，不涉及任何其他方面的内容。原则上该工具只应该在开发测试环境下与区块链的测试网进行交互调试，作者并不提倡在其他情况下使用。若开发者执意在具有经济价值的区块链主网中使用，所造成的任何影响由其个人负责，与作者本人无关。
