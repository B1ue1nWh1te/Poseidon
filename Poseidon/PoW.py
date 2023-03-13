"""
本模块用于解决连接题目环境时可能遇到的工作量证明问题，在 Linux 环境下可以正常运行。
"""

import hashlib
from pwn import *
from pwnlib.util.iters import mbruteforce


class PoWUtils():
    """
    本模块用于解决连接题目环境时可能遇到的工作量证明问题，在 Linux 环境下可以正常运行。
    """

    @staticmethod
    def ProofOfWork_SHA256_Full(Url: str, Port: int, HashBegin: str, HashEnd: str, TextLength: int, SendAfter: str) -> remote:
        """
        用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了 SHA256 的完整值，求长度为参数 (TextLength:int) 的字符串使得其 SHA256 值与给出的 SHA256 值相等。

        参数：
            Url (str): 题目环境的链接地址
            Port (int): 题目环境的端口号
            HashBegin (str): 哈希值之前的字符串
            HashEnd (str): 哈希值之后的字符串
            TextLength (int): 待求解的字符串的长度
            SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

        返回值：
            Connection (pwn.remote): 与服务器建立的连接对象
        """

        Connection = remote(Url, Port)
        Connection.recvuntil(HashBegin)
        Hash = Connection.recvuntil(HashEnd, drop=True).decode().strip()
        Charset = string.printable
        Proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == Hash, Charset, TextLength, method='fixed')
        Connection.sendlineafter(SendAfter, Proof)
        return Connection

    @staticmethod
    def ProofOfWork_SHA256_Prefix(Url: str, Port: int, PrefixBegin: str, PrefixEnd: str, PrefixLength: int, MaxTextLength: int, SendAfter: str) -> remote:
        """
        用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了 SHA256 的前缀值，求一个最大长度不超过参数 (MaxTextLength:int) 的字符串使得其 SHA256 值的前缀与给出的 SHA256 前缀相等。

        参数：
            Url (str): 题目环境的链接地址
            Port (int): 题目环境的端口号
            PrefixBegin (str): 哈希值前缀之前的字符串
            PrefixEnd (str): 哈希值前缀之后的字符串
            PrefixLength (int): 哈希值前缀的字符串的长度
            MaxTextLength (int): 待求解的字符串的最大长度
            SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

        返回值：
            Connection (pwn.remote): 与服务器建立的连接对象
        """

        Connection = remote(Url, Port)
        Connection.recvuntil(PrefixBegin)
        Prefix = Connection.recvuntil(PrefixEnd, drop=True).decode().strip()
        Charset = string.printable
        Proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest()[:PrefixLength] == Prefix, Charset, MaxTextLength, method='upto')
        Connection.sendlineafter(SendAfter, Proof)
        return Connection

    @staticmethod
    def ProofOfWork_SHA256_EndWithZero(Url: str, Port: int, KnownBegin: str, KnownEnd: str, UnknownLength: int, EndWithZeroLength: int, SendAfter: str) -> remote:
        """
        用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了原文的前一部分，剩下长度（UnknownLength:int）的部分未知，要求解出未知部分的字符串，以使得与已知部分拼接得到的字符串的 SHA256 值的二进制形式中末尾所包含的 0 的个数为（EndWithZeroLength:int）。

        参数：
            Url (str): 题目环境的链接地址
            Port (int): 题目环境的端口号
            KnownBegin (str): 已知部分之前的字符串
            KnownEnd (str): 已知部分之后的字符串
            UnknownLength (int): 未知部分的字符串的长度
            EndWithZeroLength (int): SHA256 值的二进制形式中末尾所包含的 0 的个数
            SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

        返回值：
            Connection (pwn.remote): 与服务器建立的连接对象
        """

        Connection = remote(Url, Port)
        Connection.recvuntil(KnownBegin)
        Known = Connection.recvuntil(KnownEnd, drop=True).decode().strip()
        Charset = string.printable
        Proof = mbruteforce(lambda x: bin(int(hashlib.sha256((Known + x).encode()).hexdigest(), 16)).endswith('0' * EndWithZeroLength), Charset, UnknownLength, method='fixed')
        Connection.sendlineafter(SendAfter, Proof)
        return Connection

    @staticmethod
    def ProofOfWork_MD5_Full(Url: str, Port: int, HashBegin: str, HashEnd: str, TextLength: int, SendAfter: str) -> remote:
        """
        用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了 MD5 的完整值，求长度为参数 (TextLength:int) 的字符串使得其 MD5 值与给出的 MD5 值相等。

        参数：
            Url (str): 题目环境的链接地址
            Port (int): 题目环境的端口号
            HashBegin (str): 哈希值之前的字符串
            HashEnd (str): 哈希值之后的字符串
            TextLength (int): 待求解的字符串的长度
            SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

        返回值：
            Connection (pwn.remote): 与服务器建立的连接对象
        """

        Connection = remote(Url, Port)
        Connection.recvuntil(HashBegin)
        Hash = Connection.recvuntil(HashEnd, drop=True).decode().strip()
        Charset = string.printable
        Proof = mbruteforce(lambda x: hashlib.md5((x).encode()).hexdigest() == Hash, Charset, TextLength, method='fixed')
        Connection.sendlineafter(SendAfter, Proof)
        return Connection

    @staticmethod
    def ProofOfWork_MD5_Prefix(Url: str, Port: int, PrefixBegin: str, PrefixEnd: str, PrefixLength: int, MaxTextLength: int, SendAfter: str) -> remote:
        """
        用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了 MD5 的前缀值，求一个最大长度不超过参数 (MaxTextLength:int) 的字符串使得其 MD5 值的前缀与给出的 MD5 前缀相等。

        参数：
            Url (str): 题目环境的链接地址
            Port (int): 题目环境的端口号
            PrefixBegin (str): 哈希值前缀之前的字符串
            PrefixEnd (str): 哈希值前缀之后的字符串
            PrefixLength (int): 哈希值前缀的字符串的长度
            MaxTextLength (int): 待求解的字符串的最大长度
            SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

        返回值：
            Connection (pwn.remote): 与服务器建立的连接对象
        """

        Connection = remote(Url, Port)
        Connection.recvuntil(PrefixBegin)
        Prefix = Connection.recvuntil(PrefixEnd, drop=True).decode().strip()
        Charset = string.printable
        Proof = mbruteforce(lambda x: hashlib.md5((x).encode()).hexdigest()[:PrefixLength] == Prefix, Charset, MaxTextLength, method='upto')
        Connection.sendlineafter(SendAfter, Proof)
        return Connection

    @staticmethod
    def ProofOfWork_MD5_EndWithZero(Url: str, Port: int, KnownBegin: str, KnownEnd: str, UnknownLength: int, EndWithZeroLength: int, SendAfter: str) -> remote:
        """
        用于解决连接题目环境时可能遇到的工作量证明问题，这一函数可处理以下情况：给出了原文的前一部分，剩下长度（UnknownLength:int）的部分未知，要求解出未知部分的字符串，以使得与已知部分拼接得到的字符串的 MD5 值的二进制形式中末尾所包含的 0 的个数为（EndWithZeroLength:int）。

        参数：
            Url (str): 题目环境的链接地址
            Port (int): 题目环境的端口号
            KnownBegin (str): 已知部分之前的字符串
            KnownEnd (str): 已知部分之后的字符串
            UnknownLength (int): 未知部分的字符串的长度
            EndWithZeroLength (int): MD5 值的二进制形式中末尾所包含的 0 的个数
            SendAfter (str): 在接收到这个参数所指明的字符串后才将求解出的字符串发送给服务器

        返回值：
            Connection (pwn.remote): 与服务器建立的连接对象
        """

        Connection = remote(Url, Port)
        Connection.recvuntil(KnownBegin)
        Known = Connection.recvuntil(KnownEnd, drop=True).decode().strip()
        Charset = string.printable
        Proof = mbruteforce(lambda x: bin(int(hashlib.md5((Known + x).encode()).hexdigest(), 16)).endswith('0' * EndWithZeroLength), Charset, UnknownLength, method='fixed')
        Connection.sendlineafter(SendAfter, Proof)
        return Connection
