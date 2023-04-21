from setuptools import setup
import os


def long_description():
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'README.md'), encoding='utf-8') as f:
        return f.read()


setup(
    name="poseidon-python",
    version="1.1.5",
    author="B1ue1nWh1te",
    author_email="b1ue1nwh1te@skiff.com",
    description="海神波塞冬工具对常用的链上交互操作进行了封装，使得开发者能够便捷地与任何以太坊同构链交互，主要用于在 CTF 比赛中攻克 Blockchain 方向的题目。",
    keywords=['POSEIDON', 'BLOCKCHAIN', 'EVM', 'CRYPTO', 'CTF'],
    long_description=long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/B1ue1nWh1te/Poseidon",
    license="GPL-3.0",
    packages=["Poseidon"],
    python_requires='>=3.9',
    install_requires=["web3>=6.2.0", "py-solc-x>=1.1.1", "pyevmasm>=0.2.3", "loguru>=0.7.0", "pycryptodome>=3.17", "gmpy2>=2.1.5", "pwntools>=4.9.0"],
    zip_safe=False
)
