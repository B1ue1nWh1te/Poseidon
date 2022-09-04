import hashlib
from pwn import *
from pwnlib.util.iters import mbruteforce


class PoWUtils():
    @staticmethod
    def ProofOfWork_SHA256_Full(Url: str, Port: int, Length: int, HashBegin: str, SendAfter: str) -> remote:
        Connection = remote(Url, Port)
        Connection.recvuntil(HashBegin)
        Hash = Connection.recvuntil('\n', drop=True).decode().strip()
        Charset = string.printable
        Proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == Hash, Charset, Length, method='fixed')
        Connection.sendlineafter(SendAfter, Proof)
        return Connection

    @staticmethod
    def ProofOfWork_SHA256_Prefix(Url: str, Port: int, PrefixLength: int, HashBegin: str, SendAfter: str) -> remote:
        Connection = remote(Url, Port)
        Connection.recvuntil(HashBegin)
        Prefix = Connection.recvuntil('\n', drop=True).decode().strip()
        Charset = string.printable
        Proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest()[:PrefixLength] == Prefix, Charset, 8, method='upto')
        Connection.sendlineafter(SendAfter, Proof)
        return Connection

    @staticmethod
    def ProofOfWork_MD5_Full(Url: str, Port: int, Length: int, HashBegin: str, SendAfter: str) -> remote:
        Connection = remote(Url, Port)
        Connection.recvuntil(HashBegin)
        Hash = Connection.recvuntil('\n', drop=True).decode().strip()
        Charset = string.printable
        Proof = mbruteforce(lambda x: hashlib.md5((x).encode()).hexdigest() == Hash, Charset, Length, method='fixed')
        Connection.sendlineafter(SendAfter, Proof)
        return Connection

    @staticmethod
    def ProofOfWork_MD5_Prefix(Url: str, Port: int, PrefixLength: int, HashBegin: str, SendAfter: str) -> remote:
        Connection = remote(Url, Port)
        Connection.recvuntil(HashBegin)
        Prefix = Connection.recvuntil('\n', drop=True).decode().strip()
        Charset = string.printable
        Proof = mbruteforce(lambda x: hashlib.md5((x).encode()).hexdigest()[:PrefixLength] == Prefix, Charset, 8, method='upto')
        Connection.sendlineafter(SendAfter, Proof)
        return Connection
