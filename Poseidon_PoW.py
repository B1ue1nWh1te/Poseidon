from pwn import *
from pwnlib.util.iters import mbruteforce
import hashlib


def ProofOfWork_SHA256_Full(Url, Port=80, Length=4, HashBegin=">", SendAfter=">"):
    Connection = remote(Url, Port)
    Connection.recvuntil(HashBegin)
    Hash = Connection.recvuntil('\n', drop=True).decode().strip()
    Charset = string.printable
    Proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == Hash, Charset, Length, method='fixed')
    Connection.sendlineafter(SendAfter, Proof)
    return Connection


def ProofOfWork_SHA256_Prefix(Url, Port=80, PrefixLength=4, HashBegin=">", SendAfter=">"):
    Connection = remote(Url, Port)
    Connection.recvuntil(HashBegin)
    Prefix = Connection.recvuntil('\n', drop=True).decode().strip()
    Charset = string.printable
    Proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest()[:PrefixLength] == Prefix, Charset, 8, method='upto')
    Connection.sendlineafter(SendAfter, Proof)
    return Connection


def ProofOfWork_MD5_Full(Url, Port=80, Length=4, HashBegin=">", SendAfter=">"):
    Connection = remote(Url, Port)
    Connection.recvuntil(HashBegin)
    Hash = Connection.recvuntil('\n', drop=True).decode().strip()
    Charset = string.printable
    Proof = mbruteforce(lambda x: hashlib.md5((x).encode()).hexdigest() == Hash, Charset, Length, method='fixed')
    Connection.sendlineafter(SendAfter, Proof)
    return Connection


def ProofOfWork_MD5_Prefix(Url, Port=80, PrefixLength=4, HashBegin=">", SendAfter=">"):
    Connection = remote(Url, Port)
    Connection.recvuntil(HashBegin)
    Prefix = Connection.recvuntil('\n', drop=True).decode().strip()
    Charset = string.printable
    Proof = mbruteforce(lambda x: hashlib.md5((x).encode()).hexdigest()[:PrefixLength] == Prefix, Charset, 8, method='upto')
    Connection.sendlineafter(SendAfter, Proof)
    return Connection
