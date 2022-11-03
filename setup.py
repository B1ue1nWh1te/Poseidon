from setuptools import setup

setup(
    name="poseidon-python",
    version="1.0.4",
    author="B1ue1nWh1te",
    author_email="b1ue1nwh1te@skiff.com",
    description="CTF 解题快速利用工具，是攻克 Blockchain 方向的得力助手，也包含一些 Crypto 方向的功能，可用于快速编写解题脚本而免去以往繁琐的步骤。",
    keywords=['POSEIDON', 'BLOCKCHAIN', 'ETHEREUM', 'CRYPTO', 'CTF', 'TOOLS'],
    license="GPL-3.0",
    url="https://github.com/B1ue1nWh1te/Poseidon",
    python_requires='>=3.7',
    install_requires=["web3", "py-solc-x", "loguru", "pycryptodome", "gmpy2", "pwntools"],
    packages=["Poseidon"],
    zip_safe=False
)
