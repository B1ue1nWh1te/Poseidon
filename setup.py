from setuptools import setup
import os


def long_description():
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'README.md'), encoding='utf-8') as f:
        return f.read()


setup(
    name="poseidon-python",
    version="1.0.5",
    author="B1ue1nWh1te",
    author_email="b1ue1nwh1te@skiff.com",
    description="CTF 解题快速利用工具，是攻克 Blockchain 方向的得力助手，也包含一些 Crypto 方向的功能，可用于快速编写解题脚本而免去以往繁琐的步骤。",
    keywords=['POSEIDON', 'TOOLS', 'CTF', 'BLOCKCHAIN', 'CRYPTO', 'EVM'],
    long_description=long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/B1ue1nWh1te/Poseidon",
    license="GPL-3.0",
    packages=["Poseidon"],
    python_requires='>=3.7',
    install_requires=["web3", "py-solc-x", "pyevmasm", "loguru", "pycryptodome", "gmpy2", "pwntools"],
    zip_safe=False
)
