import struct
import hashlib
import requests
import binascii
from PIL import Image
from Crypto.Util.number import long_to_bytes


def Binary_String(Binary):
    assert(len(Binary) % 8 == 0)
    String = "".join([chr(int(Binary[i:i + 8], 2)) for i in range(0, len(Binary), 8)])
    return String


def Binary_Dec(Binary):
    Dec = str(int(Binary, 2))
    return Dec


def Binary_Hex(Binary):
    Hex = hex(int(Binary, 2))
    return Hex


def Dec_String(Dec):
    String = long_to_bytes(Dec).decode()
    return String


def Dec_Binary(Dec):
    Binary = bin(int(Dec))
    return Binary


def Dec_Hex(Dec):
    Hex = hex(int(Dec))
    return Hex


def Hex_String(Hex):
    assert(len(Hex) % 2 == 0)
    String = "".join([chr(int(Hex[i:i + 2], 16)) for i in range(0, len(Hex), 2)])
    return String


def Hex_Binary(Hex):
    Binary = bin(int(Hex, 16))
    return Binary


def Hex_Dec(Hex):
    Dec = str(int(Hex, 16))
    return Dec


def File_Bytes(Course):
    with open(Course, "rb") as f:
        return f.read()


def SHA1(Text):
    Hash = hashlib.sha1().update(Text.encode()).hexdigest()
    return Hash


def SHA256(Text):
    Hash = hashlib.sha256().update(Text.encode()).hexdigest()
    return Hash


def SHA512(Text):
    Hash = hashlib.sha512().update(Text.encode()).hexdigest()
    return Hash


def MD5(Text):
    Hash = hashlib.md5().update(Text.encode()).hexdigest()
    return Hash


def CRC_Burst(Course):
    Binary = open(Course, "rb").read()
    if(int(Binary[0:8].hex(), 16) != int("0x89504e470d0a1a0a", 16)):
        print("[CRC爆破]检测到[文件头错误]，请修改第[1-8]个字节为:89 50 4E 47 0D 0A 1A 0A")
    if(int(Binary[8:12].hex(), 16) != int("0x0000000d", 16)):
        print("[CRC爆破]检测到[数据块长度错误]，请修改第[9-12]个字节为:00 00 00 0D")
    if(int(Binary[12:16].hex(), 16) != int("0x49484452", 16)):
        print("[CRC爆破]检测到[数据块标识错误]，请修改第[13-16]个字节为:49 48 44 52")
    Code = binascii.crc32(Binary[12:29]) & 0xffffffff
    CRC = int(Binary[29:33].hex(), 16)
    if(Code == CRC):
        print("[CRC爆破]CRC校验码匹配")
    else:
        print("[CRC爆破]CRC校验码不匹配 即将进行[宽度]爆破")
        for i in range(1, 4097):
            temp = struct.pack(">i", i)
            Code = binascii.crc32(bytes("IHDR", "ascii") + temp + Binary[20:29]) & 0xffffffff
            if(Code == CRC):
                print("图片正确宽度为:{} Hex:{}".format(i, hex(i)))
                return
        print("[CRC爆破][宽度]爆破失败 即将进行[高度]爆破")
        for i in range(1, 4097):
            temp = struct.pack(">i", i)
            Code = binascii.crc32(bytes("IHDR", "ascii") + Binary[16:20] + temp + Binary[24:29]) & 0xffffffff
            if(Code == CRC):
                print("图片正确高度为:{} Hex:{}".format(i, hex(i)))
                return
        print("[CRC爆破][宽高单项爆破]失败 即将进行[宽高联合爆破]")
        for i in range(4097):
            width = struct.pack(">i", i)
            for j in range(4097):
                height = struct.pack(">i", j)
                Code = binascii.crc32(bytes("IHDR", "ascii") + width + height + Binary[24:29]) & 0xffffffff
                if(Code == CRC):
                    print("[CRC爆破]宽度为:{} 高度为:{} Hex:{} {}".format(i, j, hex(i), hex(j)))
                    return
        print("[CRC爆破]爆破失败 请判断异常情况")


def BinaryToQRCode(BinaryList):
    X = Y = len(BinaryList)
    for i in range(X):
        assert(X == len(BinaryList[i]))
    image = Image.new('RGB', (X, Y))
    white = (255, 255, 255)
    black = (0, 0, 0)
    for i in range(X):
        line = BinaryList[i]
        for j in range(Y):
            if line[j] == '1':
                image.putpixel((i, j), black)
            elif line[j] == '0':
                image.putpixel((i, j), white)
    image.save("BinaryToQRCodeResult.png")
    image.show()


def RGBToImage(RGBList, X, Y, Mode="Column"):
    Board = Image.new("RGB", (X, Y))
    if Mode == "Column":
        for i in range(X):
            for j in range(Y):
                Index = i * Y + j
                Board.putpixel((i, j), tuple(eval(RGBList[Index])))
    elif Mode == "Row":
        for i in range(Y):
            for j in range(X):
                Index = i * X + j
                Board.putpixel((j, i), tuple(eval(RGBList[Index])))
    Board.save("RGBToImageResult.png")
    Board.show()


def ImageToRGB(ImageCourse, Mode="Column"):
    image = Image.open(ImageCourse)
    X = image.size[0]
    Y = image.size[1]
    imageRGB = image.convert("RGB")
    Result = []
    if Mode == "Column":
        for i in range(X):
            for j in range(Y):
                Result.append(imageRGB.getpixel((i, j)))
    elif Mode == "Row":
        for i in range(Y):
            for j in range(X):
                Result.append(imageRGB.getpixel((j, i)))
    return Result


def Request(Url, Method="GET", Headers=None, Params=None, Data=None):
    Response = requests.request(Method, Url, headers=Headers, params=Params, data=Data)
    StatusCode = Response.status_code
    ResponseHeaders = Response.headers
    Cookies = Response.cookies
    Response.encoding = Response.apparent_encoding
    ResponseText = Response.text
    ReText = Response.text.replace("\n", "").replace(" ", "")
    Result = {"StatusCode": StatusCode, "ResponseHeaders": ResponseHeaders, "Cookies": Cookies, "ResponseText": ResponseText, "ReText": ReText}
    return Result
