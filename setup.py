from setuptools import setup
import os


def long_description():
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'README.md'), encoding='utf-8') as f:
        return f.read()


setup(
    name="poseidon-python",
    version="1.1.4",
    author="B1ue1nWh1te",
    author_email="b1ue1nwh1te@skiff.com",
    description="海神波塞冬工具对常用的链上交互操作进行了封装，使得开发者能够便捷地与任何以太坊同构链交互，主要用于在CTF比赛中攻克Blockchain方向的题目。",
    keywords=['POSEIDON', 'BLOCKCHAIN', 'EVM', 'CRYPTO', 'CTF'],
    long_description=long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/B1ue1nWh1te/Poseidon",
    license="GPL-3.0",
    packages=["Poseidon"],
    python_requires='>=3.9',
    install_requires=["web3", "py-solc-x", "pyevmasm", "loguru", "pycryptodome", "gmpy2", "pwntools"],
    zip_safe=False
)
