import gmpy2
import base64
import operator
from functools import reduce
from Crypto.Cipher import ARC4
from Crypto.Cipher import AES as aes
from Crypto.Util.number import long_to_bytes, bytes_to_long


def Zodiac(Text, Foot=17):
    assert(len(Text) % Foot == 0)
    templist1 = [Text[i:i + Foot] for i in range(0, len(Text), Foot)]
    templist2 = []
    for index in range(Foot):
        temp = ""
        for i in range(0, len(templist1)):
            temp += templist1[i][index]
            index = (index + 2) % Foot
        templist2.append(temp)
    DecryptedText = "".join(templist2)
    return DecryptedText


def Yunying(Text):
    List = Text.split("0")
    DecryptedText = ""
    for i in List:
        Sum = 64
        for j in i:
            Sum += int(j)
        DecryptedText += chr(Sum)
    return DecryptedText


def Morse_Encrypt(Morse):
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
    EncryptedText = "/".join([MorseCode.get(i, "[" + i + "]") for i in Morse])
    return EncryptedText


def Morse_Decrypt(Morse):
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
    DecryptedText = "".join([MorseCode.get(i, "[" + i + "]") for i in Morse.split("/")])
    return DecryptedText


def Caesar_Encrypt(Text, Move=3):
    EncryptedText = ""
    for i in Text:
        if i.isupper():
            EncryptedText += chr((ord(i) - ord('A') + int(Move)) % 26 + ord('A'))
        elif i.islower():
            EncryptedText += chr((ord(i) - ord('a') + int(Move)) % 26 + ord('a'))
        else:
            EncryptedText += i
    return EncryptedText


def Caesar_Decrypt(Text, Move=3):
    DecryptedText = ""
    for i in Text:
        if i.isupper():
            DecryptedText += chr((ord(i) - ord('A') - int(Move)) % 26 + ord('A'))
        elif i.islower():
            DecryptedText += chr((ord(i) - ord('a') - int(Move)) % 26 + ord('a'))
        else:
            DecryptedText += i
    return DecryptedText


def Caesar_Attack(Text):
    Result = [Caesar_Decrypt(Text, i) for i in range(0, 26)]
    return Result


def Bacon_Encrypt(Bacon):
    BaconCode = {
        "a": "aaaaa", "b": "aaaab", "c": "aaaba", "d": "aaabb", "e": "aabaa", "f": "aabab", "g": "aabba",
        "h": "aabbb", "i": "abaaa", "j": "abaab", "k": "ababa", "l": "ababb", "m": "abbaa", "n": "abbab",
        "o": "abbba", "p": "abbbb", "q": "baaaa", "r": "baaab", "s": "baaba", "t": "baabb",
        "u": "babaa", "v": "babab", "w": "babba", "x": "babbb", "y": "bbaaa", "z": "bbaab",
    }
    EncryptedText = "".join([BaconCode.get(i, "[" + i + "]") for i in Bacon.lower()]).upper()
    return EncryptedText


def Bacon_Decrypt(Bacon):
    BaconCode = {
        "aaaaa": "a", "aaaab": "b", "aaaba": "c", "aaabb": "d", "aabaa": "e", "aabab": "f", "aabba": "g",
        "aabbb": "h", "abaaa": "i", "abaab": "j", "ababa": "k", "ababb": "l", "abbaa": "m", "abbab": "n",
        "abbba": "o", "abbbb": "p", "baaaa": "q", "baaab": "r", "baaba": "s", "baabb": "t",
        "babaa": "u", "babab": "v", "babba": "w", "babbb": "x", "bbaaa": "y", "bbaab": "z",
    }
    assert(len(Bacon) % 5 == 0)
    List = [Bacon.lower()[i:i + 5] for i in range(0, len(Bacon), 5)]
    DecryptText = "".join([BaconCode.get(i, "[" + i + "]") for i in List]).upper()
    return DecryptText


def Affine_Encrypt(Text, a, b):
    A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    assert(a in A)
    List = []
    for i in Text:
        if i.isupper():
            List.append(chr((a * (ord(i) - ord('A')) + b) % 26 + ord('A')))
        elif i.islower():
            List.append(chr((a * (ord(i) - ord('a')) + b) % 26 + ord('a')))
        else:
            List.append(i)
    EncryptedText = "".join(List)
    return EncryptedText


def Affine_Decrypt(Text, a, b):
    A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    assert(a in A)
    List = []
    n = 1
    while (n * a) % 26 != 1:
        n = n + 1
    for i in Text:
        if i.isupper():
            List.append(chr(n * (ord(i) - ord('A') - b) % 26 + ord('A')))
        elif i.islower():
            List.append(chr(n * (ord(i) - ord('a') - b) % 26 + ord('a')))
        else:
            List.append(i)
    DecryptedText = "".join(List)
    return DecryptedText


def Affine_Attack(Text):
    A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    Result = []
    for a in A:
        for b in range(26):
            Result.append((a, b, Affine_Decrypt(Text, a, b)))
    return Result


def Vigenere_Encrypt(Text, Key):
    Key = Key[:len(Text)]
    Temp = Key
    index = 0
    while(len(Key) < len(Text)):
        if(index != len(Temp)):
            Key += Temp[index]
            index += 1
        else:
            index = 0
            Key += Temp[index]
            index += 1
    EncryptedText = ""
    for i in range(len(Text)):
        if i.isupper():
            EncryptedText += chr((ord(Text[i]) + ord(Key[i].upper()) - 2 * ord('A')) % 26 + ord('A'))
        elif i.islower():
            EncryptedText += chr((ord(Text[i]) + ord(Key[i].lower()) - 2 * ord('a')) % 26 + ord('a'))
        else:
            EncryptedText += Text[i]
    return EncryptedText


def Vigenere_Decrypt(Text, Key):
    Key = Key[:len(Text)]
    Temp = Key
    index = 0
    while(len(Key) < len(Text)):
        if(index != len(Temp)):
            Key = Key + Temp[index]
            index = index + 1
        else:
            index = 0
            Key = Key + Temp[index]
            index = index + 1
    DecryptedText = ""
    for i in range(len(Text)):
        if i.isupper():
            DecryptedText += chr((ord(Text[i]) - ord(Key[i].upper())) % 26 + ord('A'))
        elif i.islower():
            DecryptedText += chr((ord(Text[i]) - ord(Key[i].lower())) % 26 + ord('a'))
        else:
            DecryptedText += Text[i]
    return DecryptedText


def Fence_Encrypt(Text, Fence):
    assert(len(Text) % Fence == 0)
    templist = []
    List = [Text[i:i + Fence] for i in range(0, len(Text), Fence)]
    for i in range(Fence):
        temp = ""
        for j in List:
            temp += j[i]
        templist.append(temp)
    EncryptedText = "".join(templist)
    return EncryptedText


def Fence_Decrypt(Text, Fence):
    assert(len(Text) % Fence == 0)
    templist = ["" for _ in range(Fence)]
    List = [Text[i:i + Fence] for i in range(0, len(Text), Fence)]
    for i in List:
        for j in range(Fence):
            templist[j] = templist[j] + i[j]
    DecryptedText = "".join(templist)
    return DecryptedText


def Fence_Attack(Text):
    Factors = [factor for factor in range(2, len(Text)) if len(Text) % factor == 0]
    Result = [(i, Fence_Decrypt(Text, i)) for i in Factors]
    return Result


def WFence_Generate(Text, Fence):
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


def WFence_Encrypt(Text, Fence):
    Matrix = WFence_Generate(Text, Fence)
    EncryptedText = ""
    for Row in range(Fence):
        for Column in range(len(Text)):
            if Matrix[Row][Column] != '.':
                EncryptedText += Matrix[Row][Column]
    return EncryptedText


def WFence_Decrypt(Text, Fence):
    Matrix = WFence_Generate(Text, Fence)
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


def WFence_Attack(Text):
    Result = [(i, WFence_Decrypt(Text, i)) for i in range(2, len(Text))]
    return Result


def RC4_Encrypt(Text, Key):
    RC4 = ARC4.new(Key.encode())
    EncryptedText = base64.b64encode(RC4.encrypt(Text.encode())).decode()
    return EncryptedText


def RC4_Decrypt(Text, Key):
    RC4 = ARC4.new(Key.encode())
    DecryptedText = RC4.decrypt(base64.b64decode(Text.encode())).decode()
    return DecryptedText


def AES_Fill(Text):
    Fill = Text.encode()
    while len(Fill) % 16 != 0:
        Fill += b'\x00'
    return Fill


def AES_Encrypt(Text, Key, Mode=aes.MODE_ECB):
    AES = aes.new(AES_Fill(Key), Mode)
    EncryptedText = base64.b64encode(AES.encrypt(AES_Fill(Text))).decode()
    return EncryptedText


def AES_Decrypt(Text, Key, Mode=aes.MODE_ECB):
    AES = aes.new(AES_Fill(Key), Mode)
    DecryptedText = AES.decrypt(base64.b64decode(AES_Fill(Text))).decode()
    return DecryptedText


def RSA_Encrypt(Text, p, q, e=65537):
    m = bytes_to_long(Text.encode())
    c = gmpy2.powmod(m, e, p * q)
    EncryptedText = base64.b64encode(long_to_bytes(c)).decode()
    return EncryptedText


def RSA_Base64_Decrypt(Base64, p, q, e=65537):
    c = bytes_to_long(base64.b64decode(Base64.encode()))
    d = gmpy2.invert(e, (p - 1) * (q - 1))
    m = gmpy2.powmod(c, d, p * q)
    DecryptedText = long_to_bytes(m).decode()
    return DecryptedText


def RSA_Long_Decrypt(Long, p, q, e=65537):
    d = gmpy2.invert(e, (p - 1) * (q - 1))
    m = gmpy2.powmod(Long, d, p * q)
    DecryptedText = long_to_bytes(m).decode()
    return DecryptedText


def continuedFra(x, y):
    """计算连分数
    :param x: 分子
    :param y: 分母
    :return: 连分数列表
    """
    cf = []
    while y:
        cf.append(x // y)
        x, y = y, x % y
    return cf


def gradualFra(cf):
    """计算传入列表最后的渐进分数
    :param cf: 连分数列表
    :return: 该列表最后的渐近分数
    """
    numerator = 0
    denominator = 1
    for x in cf[::-1]:
        # 这里的渐进分数分子分母要分开
        numerator, denominator = denominator, x * denominator + numerator
    return numerator, denominator


def solve_pq(a, b, c):
    """使用韦达定理解出pq，x^2−(p+q)∗x+pq=0
    :param a:x^2的系数
    :param b:x的系数
    :param c:pq
    :return:p，q
    """
    par = gmpy2.isqrt(b * b - 4 * a * c)
    return (-b + par) // (2 * a), (-b - par) // (2 * a)


def getGradualFra(cf):
    """计算列表所有的渐近分数
    :param cf: 连分数列表
    :return: 该列表所有的渐近分数
    """
    gf = []
    for i in range(1, len(cf) + 1):
        gf.append(gradualFra(cf[:i]))
    return gf


def RSA_Wiener_Attack(c, e, n):
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


def RSA_MultiPrime_Attack(c, e, n, primes, powers=None):
    if powers == None:
        powers = [1 for _ in range(len(primes))]
    assert(len(primes) == len(powers))
    temp = [pow(primes[i], powers[i] - 1) * (primes[i] - 1) for i in range(len(primes))]
    phi = reduce(operator.mul, temp)
    d = gmpy2.invert(e, phi)
    m = long_to_bytes(gmpy2.powmod(c, d, n)).decode()
    return m


def RSA_LowEncryptionIndex_Attack(c, e, n):
    k = 0
    while True:
        m = gmpy2.iroot(c + k * n, e)[0]
        if type(m) == type(gmpy2.mpz(0)):
            m = long_to_bytes(m).decode()
            return m
        else:
            k += 1
            continue


def RSA_CommonMod_Attack(c1, c2, e1, e2, n):
    g, x, y = gmpy2.gcdext(e1, e2)
    m = long_to_bytes((gmpy2.powmod(c1, x, n) * gmpy2.powmod(c2, y, n)) % n).decode()
    return m


def RSA_Broadcast_Attack(cs, e, ns):
    assert(len(cs) == len(ns))
    s = 0
    prod = reduce(lambda a, b: a * b, ns)
    for ni, ai in zip(ns, cs):
        p = prod / ni
        s += ai + gmpy2.invert(p, ni) * p
    x = s % prod
    m = long_to_bytes(gmpy2.iroot(x, e)).decode()
    return m


def Base64_Encrypt(Text):
    try:
        EncryptedText = base64.b64encode(Text.encode()).decode()
        return EncryptedText
    except:
        return "[Base64]加密错误"


def Base64_Decrypt(Text):
    try:
        DecryptedText = base64.b64decode(Text.encode()).decode()
        return DecryptedText
    except:
        return "[Base64]解密错误"


def Base64_Stego_Decrypt(Base64List):
    Base64Code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    Binary = ""
    for line in Base64List:
        if "==" in line:
            temp = bin(Base64Code.find(line[-3]) & 15)[2:]  # 通过按位与&15运算取出二进制数后4位 [2:]的作用是将0b过滤掉
            Binary += "0" * (4 - len(temp)) + temp  # 高位补0
        elif "=" in line:
            temp = bin(Base64Code.find(line[-2]) & 3)[2:]  # 通过按位与&3运算取出二进制数后2位
            Binary += "0" * (2 - len(temp)) + temp  # 高位补0
    Text = ""
    if(len(Binary) % 8 != 0):  # 最终得到的隐写数据二进制位数不一定都是8的倍数，为了避免数组越界，加上一个判断
        print("[Base64隐写]将进行不完整解析")
        for i in range(0, len(Binary), 8):
            if(i + 8 > len(Binary)):
                Text += " 剩余位:" + Binary[i:]
                return Text
            else:
                Text += chr(int(Binary[i:i + 8], 2))
    else:
        Text = "".join([chr(int(Binary[i:i + 8], 2)) for i in range(0, len(Binary), 8)])
        return Text


def Base32_Encrypt(Text):
    try:
        EncryptedText = base64.b32encode(Text.upper().encode()).decode()
        return EncryptedText
    except:
        return "[Base32]加密错误"


def Base32_Decrypt(Text):
    try:
        DecryptedText = base64.b32decode(Text.upper().encode()).decode()
        return DecryptedText
    except:
        return "[Base32]解密错误"


def Base16_Encrypt(Text):
    try:
        EncryptedText = base64.b16encode(Text.upper().encode()).decode()
        return EncryptedText
    except:
        return "[Base16]加密错误"


def Base16_Decrypt(Text):
    try:
        DecryptedText = base64.b16decode(Text.upper().encode()).decode()
        return DecryptedText
    except:
        return "[Base16]解密错误"
