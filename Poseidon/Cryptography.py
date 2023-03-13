"""
本模块用于解决常见的密码学问题。
"""

import gmpy2
import base64
from Crypto.Cipher import AES as aes
from Crypto.Util.number import long_to_bytes, bytes_to_long
from typing import Optional, List


class MiscUtils():
    """
    本模块用于处理进制转换和常用哈希。静态类，无需实例化。
    """

    @staticmethod
    def Binary_String(Binary: str) -> str:
        """
        用于将形如"1010...0101"的二进制字符串按照"8位1字符"的规则转换为字符串。

        参数：
            Binary (str): 二进制字符串

        返回值：
            String (str): 转换得到的字符串
        """

        if len(Binary) % 8 != 0:
            raise Exception("二进制字符串的长度应该为8的倍数")
        String = "".join([chr(int(Binary[i:i + 8], 2)) for i in range(0, len(Binary), 8)])
        return String

    @staticmethod
    def Binary_Dec(Binary: str) -> int:
        """
        用于将形如"1010...0101"的二进制字符串转换为十进制整数形式。

        参数：
            Binary (str): 二进制字符串

        返回值：
            Dec (int): 转换得到的十进制整数
        """

        Dec = int(Binary, 2)
        return Dec

    @staticmethod
    def Binary_Hex(Binary: str) -> str:
        """
        用于将形如"1010...0101"的二进制字符串转换为十六进制字符串形式（含 0x 前缀）。

        参数：
            Binary (str): 二进制字符串

        返回值：
            Hex (str): 转换得到的十六进制字符串
        """

        Hex = hex(int(Binary, 2))
        return Hex

    @staticmethod
    def Dec_String(Dec: int) -> str:
        """
        用于将十进制整数转换为字符串（UTF-8 字符集）。

        参数：
            Dec (int): 十进制整数

        返回值：
            String (str): 转换得到的字符串
        """

        from Crypto.Util.number import long_to_bytes
        String = long_to_bytes(Dec).decode()
        return String

    @staticmethod
    def Dec_Binary(Dec: int) -> str:
        """
        用于将十进制整数转换为二进制字符串形式（含 0b 前缀）。

        参数：
            Dec (int): 十进制整数

        返回值：
            Binary (str): 转换得到的二进制字符串
        """

        Binary = bin(Dec)
        return Binary

    @staticmethod
    def Dec_Hex(Dec: int) -> str:
        """
        用于将十进制整数转换为十六进制字符串形式（含 0x 前缀）。

        参数：
            Dec (int): 十进制整数

        返回值：
            Hex (str): 转换得到的十六进制字符串
        """

        Hex = hex(Dec)
        return Hex

    @staticmethod
    def Hex_String(Hex: str) -> str:
        """
        用于将形如"0a0b0c...1c1b1a"的十六进制字符串按照"2位1字符"的规则转换为字符串。

        参数：
            Hex (str): 十六进制字符串

        返回值：
            String (str): 转换得到的字符串
        """

        if len(Hex) % 2 != 0:
            raise Exception("十六进制字符串的长度应该为2的倍数")
        String = "".join([chr(int(Hex[i:i + 2], 16)) for i in range(0, len(Hex), 2)])
        return String

    @staticmethod
    def Hex_Binary(Hex: str) -> str:
        """
        用于将形如"0a0b0c...1c1b1a"的十六进制字符串为二进制字符串形式（含 0b 前缀）。

        参数：
            Hex (str): 十六进制字符串

        返回值：
            Binary (str): 转换得到的二进制字符串
        """

        Binary = bin(int(Hex, 16))
        return Binary

    @staticmethod
    def Hex_Dec(Hex: str) -> int:
        """
        用于将形如"0a0b0c...1c1b1a"的十六进制字符串为十进制整数形式。

        参数：
            Hex (str): 十六进制字符串

        返回值：
            Dec (int): 转换得到的十进制整数
        """

        Dec = int(Hex, 16)
        return Dec

    @staticmethod
    def SHA1(Text: str) -> str:
        """
        用于获取字符串的 SHA1 哈希值。

        参数：
            Text (str): 字符串

        返回值：
            Hash (str): 该字符串的 SHA1 哈希值（十六进制字符串，不含 0x 前缀）
        """

        from hashlib import sha1
        Hash = sha1(Text.encode()).hexdigest()
        return Hash

    @staticmethod
    def SHA256(Text: str) -> str:
        """
        用于获取字符串的 SHA256 哈希值。

        参数：
            Text (str): 字符串

        返回值：
            Hash (str): 该字符串的 SHA256 哈希值（十六进制字符串，不含 0x 前缀）
        """

        from hashlib import sha256
        Hash = sha256(Text.encode()).hexdigest()
        return Hash

    @staticmethod
    def SHA512(Text: str) -> str:
        """
        用于获取字符串的 SHA512 哈希值。

        参数：
            Text (str): 字符串

        返回值：
            Hash (str): 该字符串的 SHA512 哈希值（十六进制字符串，不含 0x 前缀）
        """

        from hashlib import sha512
        Hash = sha512(Text.encode()).hexdigest()
        return Hash

    @staticmethod
    def MD5(Text: str) -> str:
        """
        用于获取字符串的 MD5 哈希值。

        参数：
            Text (str): 字符串

        返回值：
            Hash (str): 该字符串的 MD5 哈希值（十六进制字符串，不含 0x 前缀）
        """

        from hashlib import md5
        Hash = md5(Text.encode()).hexdigest()
        return Hash


class ModernCryptoUtils():
    """
    本模块用于解决现代密码学问题。
    """

    @staticmethod
    def Base64_Encrypt(Text: str) -> str:
        """
        用于对字符串进行 Base64 编码。

        参数：
            Text (str): 待编码的字符串

        返回值：
            EncryptedText (str): Base64 编码后的字符串
        """

        EncryptedText = base64.b64encode(Text.encode()).decode()
        return EncryptedText

    @staticmethod
    def Base64_Decrypt(Text: str) -> str:
        """
        用于对 Base64 编码的字符串进行解码。

        参数：
            Text (str): 待解码的 Base64 编码字符串

        返回值：
            DecryptedText (str): Base64 解码后的字符串
        """

        DecryptedText = base64.b64decode(Text.encode()).decode()
        return DecryptedText

    @staticmethod
    def Base32_Encrypt(Text: str) -> str:
        """
        用于对字符串进行 Base32 编码。

        参数：
            Text (str): 待编码的字符串

        返回值：
            EncryptedText (str): Base32 编码后的字符串
        """

        EncryptedText = base64.b32encode(Text.upper().encode()).decode()
        return EncryptedText

    @staticmethod
    def Base32_Decrypt(Text: str) -> str:
        """
        用于对 Base32 编码的字符串进行解码。

        参数：
            Text (str): 待解码的 Base32 编码字符串

        返回值：
            DecryptedText (str): Base32 解码后的字符串
        """

        DecryptedText = base64.b32decode(Text.upper().encode()).decode()
        return DecryptedText

    @staticmethod
    def Base16_Encrypt(Text: str) -> str:
        """
        用于对字符串进行 Base16 编码。

        参数：
            Text (str): 待编码的字符串

        返回值：
            EncryptedText (str): Base16 编码后的字符串
        """

        EncryptedText = base64.b16encode(Text.upper().encode()).decode()
        return EncryptedText

    @staticmethod
    def Base16_Decrypt(Text: str) -> str:
        """
        用于对 Base16 编码的字符串进行解码。

        参数：
            Text (str): 待解码的 Base16 编码字符串

        返回值：
            DecryptedText (str): Base16 解码后的字符串
        """

        DecryptedText = base64.b16decode(Text.upper().encode()).decode()
        return DecryptedText

    @staticmethod
    def AES_Padding(Text: str, BlockSize: int = 16) -> bytes:
        """
        用于对字符串进行 zeropadding 处理。

        参数：
            Text (str): 待 padding 的字符串
            BlockSize (可选)(int): 块大小（单位为字节），默认为16字节

        返回值：
            Fill (bytes): padding 后的字节数据
        """

        Fill = Text.encode()
        while len(Fill) % BlockSize != 0:
            Fill += b'\x00'
        return Fill

    @staticmethod
    def AES_Encrypt(Text: str, Key: str, BlockSize: int = 16) -> str:
        """
        用于对字符串进行 AES 加密（仅支持 ECB zeropadding 模式）。

        参数：
            Text (str): 待进行 AES 加密的字符串
            Key (str): 加密密钥
            BlockSize (可选)(int): 块大小（单位为字节），默认为16字节

        返回值：
            EncryptedText (str): AES 加密后的密文（Base64 编码形式）
        """

        AES = aes.new(ModernCryptoUtils.AES_Padding(Key, BlockSize), aes.MODE_ECB)
        EncryptedText = base64.b64encode(AES.encrypt(ModernCryptoUtils.AES_Padding(Text, BlockSize))).decode()
        return EncryptedText

    @staticmethod
    def AES_Decrypt(Text: str, Key: str, BlockSize: int = 16) -> str:
        """
        用于对 AES 密文进行解密（仅支持 ECB zeropadding 模式）。

        参数：
            Text (str): 待解密的 AES 密文（Base64 编码形式）
            Key (str): 解密密钥
            BlockSize (可选)(int): 块大小（单位为字节），默认为16字节

        返回值：
            DecryptedText (str): AES 解密后得到的原文
        """

        AES = aes.new(ModernCryptoUtils.AES_Padding(Key, BlockSize), aes.MODE_ECB)
        DecryptedText = AES.decrypt(base64.b64decode(ModernCryptoUtils.AES_Padding(Text, BlockSize))).decode()
        return DecryptedText

    @staticmethod
    def RSA_Encrypt(Text: str, p: int, q: int, e: int) -> str:
        """
        用于对字符串进行 RSA 加密。

        参数：
            Text (str): 待进行 RSA 加密的字符串
            p (int): p 值
            q (int): q 值
            e (int): e 值

        返回值：
            EncryptedText (str): RSA 加密后的密文（ Base64 编码形式）
        """

        m = bytes_to_long(Text.encode())
        c = gmpy2.powmod(m, e, p * q)
        EncryptedText = base64.b64encode(long_to_bytes(c)).decode()
        return EncryptedText

    @staticmethod
    def RSA_Base64_Decrypt(Base64Text: str, p: int, q: int, e: int) -> str:
        """
        用于对 Base64 编码形式的 RSA 密文进行解密。

        参数：
            Base64Text (str): 待进行解密的 Base64 编码形式的 RSA 密文
            p (int): p 值
            q (int): q 值
            e (int): e 值

        返回值：
            DecryptedText (str): RSA 解密后得到的原文
        """

        c = bytes_to_long(base64.b64decode(Base64Text.encode()))
        d = gmpy2.invert(e, (p - 1) * (q - 1))
        m = gmpy2.powmod(c, d, p * q)
        DecryptedText = long_to_bytes(m).decode()
        return DecryptedText

    @staticmethod
    def RSA_Long_Decrypt(Long: int, p: int, q: int, e: int) -> str:
        """
        用于对长整数形式的 RSA 密文进行解密。

        参数：
            Long (int): 待进行解密的长整数形式的 RSA 密文
            p (int): p 值
            q (int): q 值
            e (int): e 值

        返回值：
            DecryptedText (str): RSA 解密后得到的原文
        """

        d = gmpy2.invert(e, (p - 1) * (q - 1))
        m = gmpy2.powmod(Long, d, p * q)
        DecryptedText = long_to_bytes(m).decode()
        return DecryptedText

    @staticmethod
    def RSA_Wiener_Attack(c: int, e: int, n: int) -> str:
        """
        用于对长整数形式的 RSA 密文进行维纳攻击并解出原文。

        参数：
            c (int): 待进行维纳攻击的长整数形式的 RSA 密文
            e (int): e 值
            n (int): n 值

        返回值：
            m (str): RSA 维纳攻击后得到的原文
        """

        def continuedFra(x, y):
            """
            计算连分数

            参数：
                x: 分子
                y: 分母

            返回值：
                cf: 连分数列表
            """

            cf = []
            while y:
                cf.append(x // y)
                x, y = y, x % y
            return cf

        def gradualFra(cf):
            """
            计算连分数列表的最后的渐进分数

            参数：
                cf: 连分数列表

            返回值：
                numerator, denominator: 该列表最后的渐近分数（这里的渐进分数分子分母要分开）
            """

            numerator = 0
            denominator = 1
            for x in cf[::-1]:
                numerator, denominator = denominator, x * denominator + numerator
            return numerator, denominator

        def solve_pq(a, b, c):
            """
            使用韦达定理解出 pq (x^2−(p+q)∗x+pq=0)

            参数：
                a: x^2的系数
                b: x 的系数
                c: pq

            返回值：
                p, q: p 和 q 的值
            """

            par = gmpy2.isqrt(b * b - 4 * a * c)
            return (-b + par) // (2 * a), (-b - par) // (2 * a)

        def getGradualFra(cf):
            """
            计算连分数列表的所有的渐近分数

            参数：
                cf: 连分数列表

            返回值：
                gf: 该列表所有的渐近分数
            """

            gf = []
            for i in range(1, len(cf) + 1):
                gf.append(gradualFra(cf[:i]))
            return gf

        cf = continuedFra(e, n)
        gf = getGradualFra(cf)
        for d, k in gf:
            if k == 0:
                continue
            if (e * d - 1) % k != 0:
                continue
            phi = (e * d - 1) // k
            p, q = solve_pq(1, n - phi + 1, n)
            if p * q == n:
                m = long_to_bytes(gmpy2.powmod(c, d, n)).decode()
                return m

    @staticmethod
    def RSA_MultiPrime_Attack(c: int, e: int, n: int, primes: List[int], powers: Optional[List[int]] = None) -> str:
        """
        用于对长整数形式的 RSA 密文进行多素数攻击并解出原文。

        参数：
            c (int): 待进行多素数攻击的长整数形式的 RSA 密文
            e (int): e 值
            n (int): n 值
            primes (List[int]): 用于攻击的多素数列表
            powers (Optional[List[int]]): 各素数对应的阶数，默认均为 1 次方

        返回值：
            m (str): RSA 多素数攻击后得到的原文
        """

        from operator import mul
        from functools import reduce
        if powers == None:
            powers = [1 for _ in range(len(primes))]
        if len(primes) != len(powers):
            raise Exception("素数列表长度与阶数列表长度不一致")
        temp = [pow(primes[i], powers[i] - 1) * (primes[i] - 1) for i in range(len(primes))]
        phi = reduce(mul, temp)
        d = gmpy2.invert(e, phi)
        m = long_to_bytes(gmpy2.powmod(c, d, n)).decode()
        return m

    @staticmethod
    def RSA_LowEncryptionIndex_Attack(c: int, e: int, n: int) -> str:
        """
        用于对长整数形式的 RSA 密文进行低加密指数攻击并解出原文（尝试 10 万次累加 n 超过后会抛出异常）。

        参数：
            c (int): 待进行低加密指数攻击的长整数形式的 RSA 密文
            e (int): e 值
            n (int): n 值

        返回值：
            m (str): RSA 低加密指数攻击后得到的原文
        """

        k = 0
        while k < 10**5:
            m = gmpy2.iroot(c + k * n, e)[0]
            try:
                m = long_to_bytes(m).decode()
                return m
            except:
                k += 1
                continue
        raise Exception("尝试次数过多，攻击失败")

    @staticmethod
    def RSA_CommonMod_Attack(c1: int, c2: int, e1: int, e2: int, n: int) -> str:
        """
        用于对长整数形式的 RSA 密文进行共模攻击并解出原文。

        参数：
            c1 (int): 待进行共模攻击的长整数形式的第一串 RSA 密文
            c2 (int): 待进行共模攻击的长整数形式的第二串 RSA 密文
            e1 (int): c1 的 e 值
            e2 (int): c2 的 e 值
            n (int): n 值

        返回值：
            m (str): RSA 共模攻击后得到的原文
        """

        _, x, y = gmpy2.gcdext(e1, e2)
        m = long_to_bytes((gmpy2.powmod(c1, x, n) * gmpy2.powmod(c2, y, n)) % n).decode()
        return m

    @staticmethod
    def RSA_Broadcast_Attack(cs: List[int], e: int, ns: List[int]) -> str:
        """
        用于对长整数形式的 RSA 密文列表进行广播攻击并解出原文。

        参数：
            cs (List[int]): 待进行广播攻击的长整数形式的 RSA 密文列表
            e (int): e 值
            ns (List[int]): 各密文对应的 n 值的列表

        返回值：
            m (str): RSA 广播攻击后得到的原文
        """

        from functools import reduce
        if len(cs) != len(ns):
            raise Exception("密文列表长度与 n 值列表长度不一致")
        s = 0
        prod = reduce(lambda a, b: a * b, ns)
        for ni, ai in zip(ns, cs):
            p = prod // ni
            s += ai * gmpy2.invert(p, ni) * p
        x = s % prod
        m = long_to_bytes(gmpy2.iroot(x, e)[0]).decode()
        return m

    @staticmethod
    def RC4_Encrypt(Text: str, Key: str) -> str:
        """
        用于对字符串进行 RC4 加密。

        参数：
            Text (str): 待进行 RC4 加密的字符串
            Key (str): 加密密钥

        返回值：
            EncryptedText (str): RC4 加密后得到的密文（ Base64 编码形式）
        """

        from Crypto.Cipher import ARC4
        RC4 = ARC4.new(Key.encode())
        EncryptedText = base64.b64encode(RC4.encrypt(Text.encode())).decode()
        return EncryptedText

    @staticmethod
    def RC4_Decrypt(Text: str, Key: str) -> str:
        """
        用于对 Base64 编码形式的 RC4 密文进行解密。

        参数：
            Text (str): 待解密的 Base64 编码形式的 RC4 密文
            Key (str): 解密密钥

        返回值：
            DecryptedText (str): RC4 解密后得到的原文
        """

        from Crypto.Cipher import ARC4
        RC4 = ARC4.new(Key.encode())
        DecryptedText = RC4.decrypt(base64.b64decode(Text.encode())).decode()
        return DecryptedText


class ClassicalCryptoUtils():
    """
    本模块用于解决古典密码学问题。
    """

    @staticmethod
    def Caesar_Encrypt(Text: str, Move: int = 3) -> str:
        """
        用于对字符串进行 Caesar 加密。

        参数：
            Text (str): 待进行 Caesar 加密的字符串
            Move (可选)(int): 移位位数，默认为 3 

        返回值：
            EncryptedText (str): Caesar 加密后得到的密文
        """

        EncryptedText = ""
        for i in Text:
            if i.isupper():
                EncryptedText += chr((ord(i) - ord('A') + int(Move)) % 26 + ord('A'))
            elif i.islower():
                EncryptedText += chr((ord(i) - ord('a') + int(Move)) % 26 + ord('a'))
            else:
                EncryptedText += i
        return EncryptedText

    @staticmethod
    def Caesar_Decrypt(Text: str, Move: int = 3) -> str:
        """
        用于对 Caesar 密文进行解密。

        参数：
            Text (str): 待进行解密的 Caesar 密文
            Move (可选)(int): 移位位数，默认为 3 

        返回值：
            DecryptedText (str): Caesar 解密后得到的原文
        """

        DecryptedText = ""
        for i in Text:
            if i.isupper():
                DecryptedText += chr((ord(i) - ord('A') - int(Move)) % 26 + ord('A'))
            elif i.islower():
                DecryptedText += chr((ord(i) - ord('a') - int(Move)) % 26 + ord('a'))
            else:
                DecryptedText += i
        return DecryptedText

    @staticmethod
    def Caesar_Attack(Text: str) -> List[str]:
        """
        用于对 Caesar 密文进行爆破攻击。

        参数：
            Text (str): 待进行爆破攻击的 Caesar 密文

        返回值：
            Result (List[str]): Caesar 爆破攻击后得到的字符串列表
        """

        Result = [ClassicalCryptoUtils.Caesar_Decrypt(Text, i) for i in range(1, 27)]
        return Result

    @staticmethod
    def Morse_Encrypt(Text: str) -> str:
        """
        用于对字符串进行 Morse 加密。

        参数：
            Text (str): 待进行 Morse 加密的字符串

        返回值：
            EncryptedText (str): Morse 加密后得到的密文（未找到映射关系的字符将保持不变）
        """

        MorseCode = {
            "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.",
            "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--",
            "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...",
            "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
            "Z": "--..", "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".",
            "f": "..-.", "g": "--.", "h": "....", "i": "..", "j": ".---", "k": "-.-",
            "l": ".-..", "m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-",
            "r": ".-.", "s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--",
            "x": "-..-", "y": "-.--", "z": "--..", "0": "-----", "1": ".----", "2": "..---",
            "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..",
            "9": "----.", ".": ".-.-.-", ":": "---...", ",": "--..--", ";": "-.-.-.", "?": "..--..",
            "=": "-...-", "'": ".----.", "/": "-..-.", "!": "-.-.--", "-": "-....-", "_": "..--.-",
            '"': ".-..-.", "(": "-.--.", ")": "-.--.-", "$": "...-..-", "&": ".-...", "@": ".--.-.", "+": ".-.-."
        }
        EncryptedText = "/".join([MorseCode.get(i, i) for i in Text])
        return EncryptedText

    @staticmethod
    def Morse_Decrypt(Text: str) -> str:
        """
        用于对 Morse 密文进行解密。

        参数：
            Text (str): 待进行解密的 Morse 密文（以'/'进行分隔）

        返回值：
            DecryptedText (str): Morse 解密后得到的原文（未找到映射关系的字符将保持不变）
        """

        MorseCode = {
            ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
            "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
            "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
            "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
            "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
            "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
            ".-.-.-": ".", "---...": ":", "--..--": ",", "-.-.-.": ";", "..--..": "?", "-...-": "=",
            ".----.": "'", "-..-.": "/", "-.-.--": "!", "-....-": "-", "..--.-": "_", ".-..-.": '"',
            "-.--.": "(", "-.--.-": ")", "...-..-": "$", ".-...": "&", ".--.-.": "@", ".-.-.": "+"
        }
        DecryptedText = "".join([MorseCode.get(i, "[" + i + "]") for i in Text.split("/")])
        return DecryptedText

    @staticmethod
    def Bacon_Encrypt(Text: str) -> str:
        """
        用于对字符串进行 Bacon 加密。

        参数：
            Text (str): 待进行 Bacon 加密的字符串

        返回值：
            EncryptedText (str): Bacon 加密后得到的密文（大写形式 未找到映射关系的字符将以[]包裹）
        """

        BaconCode = {
            "a": "aaaaa", "b": "aaaab", "c": "aaaba", "d": "aaabb", "e": "aabaa", "f": "aabab", "g": "aabba",
            "h": "aabbb", "i": "abaaa", "j": "abaab", "k": "ababa", "l": "ababb", "m": "abbaa", "n": "abbab",
            "o": "abbba", "p": "abbbb", "q": "baaaa", "r": "baaab", "s": "baaba", "t": "baabb",
            "u": "babaa", "v": "babab", "w": "babba", "x": "babbb", "y": "bbaaa", "z": "bbaab",
        }
        EncryptedText = "".join([BaconCode.get(i, "[" + i + "]") for i in Text.lower()]).upper()
        return EncryptedText

    @staticmethod
    def Bacon_Decrypt(Text: str) -> str:
        """
        用于对 Bacon 密文进行解密。

        参数：
            Text (str): 待进行解密的 Bacon 密文

        返回值：
            DecryptedText (str): Bacon 解密后得到的原文（大写形式 未找到映射关系的字符将以[]包裹）
        """

        if len(Text) % 5 != 0:
            raise Exception("Bacon 密文应该为 5 的倍数")
        BaconCode = {
            "aaaaa": "a", "aaaab": "b", "aaaba": "c", "aaabb": "d", "aabaa": "e", "aabab": "f", "aabba": "g",
            "aabbb": "h", "abaaa": "i", "abaab": "j", "ababa": "k", "ababb": "l", "abbaa": "m", "abbab": "n",
            "abbba": "o", "abbbb": "p", "baaaa": "q", "baaab": "r", "baaba": "s", "baabb": "t",
            "babaa": "u", "babab": "v", "babba": "w", "babbb": "x", "bbaaa": "y", "bbaab": "z",
        }
        List = [Text.lower()[i:i + 5] for i in range(0, len(Text), 5)]
        DecryptText = "".join([BaconCode.get(i, "[" + i + "]") for i in List]).upper()
        return DecryptText

    @staticmethod
    def Fence_Encrypt(Text: str, Fence: int) -> str:
        """
        用于对字符串进行 Fence 加密。

        参数：
            Text (str): 待进行 Fence 加密的字符串
            Fence (int): 栏数

        返回值：
            EncryptedText (str): Fence 加密后得到的密文
        """

        if len(Text) % Fence != 0:
            raise Exception("字符串长度应该为栏数的倍数")
        templist = []
        List = [Text[i:i + Fence] for i in range(0, len(Text), Fence)]
        for i in range(Fence):
            temp = ""
            for j in List:
                temp += j[i]
            templist.append(temp)
        EncryptedText = "".join(templist)
        return EncryptedText

    @staticmethod
    def Fence_Decrypt(Text: str, Fence: int) -> str:
        """
        用于对 Fence 密文进行解密。

        参数：
            Text (str): 待进行解密的 Fence 密文
            Fence (int): 栏数

        返回值：
            DecryptedText (str): Fence 解密后得到的原文
        """

        if len(Text) % Fence != 0:
            raise Exception("字符串长度应该为栏数的倍数")
        templist = ["" for _ in range(Fence)]
        List = [Text[i:i + Fence] for i in range(0, len(Text), Fence)]
        for i in List:
            for j in range(Fence):
                templist[j] = templist[j] + i[j]
        DecryptedText = "".join(templist)
        return DecryptedText

    @staticmethod
    def Fence_Attack(Text: str) -> List[tuple]:
        """
        用于对 Fence 密文进行爆破攻击。

        参数：
            Text (str): 待进行爆破攻击的 Fence 密文

        返回值：
            Result (List[tuple]): Fence 爆破攻击后得到的元组列表（字符串, 栏数）
        """

        Factors = [factor for factor in range(2, len(Text)) if len(Text) % factor == 0]
        Result = [(ClassicalCryptoUtils.Fence_Decrypt(Text, i), i) for i in Factors]
        return Result

    @staticmethod
    def WFence_Generate(Text: str, Fence: int) -> List[List[str]]:
        """
        用于生成 WFence 矩阵以便后续处理。

        参数：
            Text (str): 待进行 WFence 处理的字符串
            Fence (int): 栏数

        返回值：
            Matrix (List[List[str]]): 生成的 WFence 矩阵
        """

        Matrix = [['.'] * len(Text) for _ in range(Fence)]
        Row = 0
        Up = False
        for Column in range(len(Text)):
            Matrix[Row][Column] = Text[Column]
            if Row == Fence - 1:
                Up = True
            if Row == 0:
                Up = False
            if Up:
                Row -= 1
            else:
                Row += 1
        return Matrix

    @staticmethod
    def WFence_Encrypt(Text: str, Fence: int) -> str:
        """
        用于对字符串进行 WFence 加密。

        参数：
            Text (str): 待进行 WFence 加密的字符串
            Fence (int): 栏数

        返回值：
            EncryptedText (str): WFence 加密后得到的密文
        """

        Matrix = ClassicalCryptoUtils.WFence_Generate(Text, Fence)
        EncryptedText = ""
        for Row in range(Fence):
            for Column in range(len(Text)):
                if Matrix[Row][Column] != '.':
                    EncryptedText += Matrix[Row][Column]
        return EncryptedText

    @staticmethod
    def WFence_Decrypt(Text: str, Fence: int) -> str:
        """
        用于对 WFence 密文进行解密。

        参数：
            Text (str): 待进行解密的 WFence 密文
            Fence (int): 栏数

        返回值：
            DecryptedText (str): WFence 解密后得到的原文
        """

        Matrix = ClassicalCryptoUtils.WFence_Generate(Text, Fence)
        index = 0
        for Row in range(Fence):
            for Column in range(len(Text)):
                if Matrix[Row][Column] != '.':
                    Matrix[Row][Column] = Text[index]
                    index += 1
        DecryptedText = ""
        for Column in range(len(Text)):
            for Row in range(Fence):
                if Matrix[Row][Column] != '.':
                    DecryptedText += Matrix[Row][Column]
        return DecryptedText

    @staticmethod
    def WFence_Attack(Text: str) -> List[tuple]:
        """
        用于对 WFence 密文进行爆破攻击。

        参数：
            Text (str): 待进行爆破攻击的 WFence 密文

        返回值：
            Result (List[tuple]): WFence 爆破攻击后得到的元组列表（字符串, 栏数）
        """

        Result = [(ClassicalCryptoUtils.WFence_Decrypt(Text, i), i) for i in range(2, len(Text))]
        return Result
