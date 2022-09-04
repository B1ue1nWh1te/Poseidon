class MiscUtils():
    @staticmethod
    def Binary_String(Binary: str) -> str:
        assert(len(Binary) % 8 == 0)
        String = "".join([chr(int(Binary[i:i + 8], 2)) for i in range(0, len(Binary), 8)])
        return String

    @staticmethod
    def Binary_Dec(Binary: str) -> str:
        Dec = str(int(Binary, 2))
        return Dec

    @staticmethod
    def Binary_Hex(Binary: str) -> str:
        Hex = hex(int(Binary, 2))
        return Hex

    @staticmethod
    def Dec_String(Dec: int) -> str:
        from Crypto.Util.number import long_to_bytes
        String = long_to_bytes(Dec).decode()
        return String

    @staticmethod
    def Dec_Binary(Dec: int) -> bytes:
        Binary = bin(Dec)
        return Binary

    @staticmethod
    def Dec_Hex(Dec: int) -> str:
        Hex = hex(Dec)
        return Hex

    @staticmethod
    def Hex_String(Hex: str) -> str:
        assert(len(Hex) % 2 == 0)
        String = "".join([chr(int(Hex[i:i + 2], 16)) for i in range(0, len(Hex), 2)])
        return String

    @staticmethod
    def Hex_Binary(Hex: str) -> bytes:
        Binary = bin(int(Hex, 16))
        return Binary

    @staticmethod
    def Hex_Dec(Hex: str) -> str:
        Dec = str(int(Hex, 16))
        return Dec

    @staticmethod
    def SHA1(Text: str) -> str:
        from hashlib import sha1
        Hash = sha1(Text.encode()).hexdigest()
        return Hash

    @staticmethod
    def SHA256(Text: str) -> str:
        from hashlib import sha256
        Hash = sha256(Text.encode()).hexdigest()
        return Hash

    @staticmethod
    def SHA512(Text: str) -> str:
        from hashlib import sha512
        Hash = sha512(Text.encode()).hexdigest()
        return Hash

    @staticmethod
    def MD5(Text: str) -> str:
        from hashlib import md5
        Hash = md5(Text.encode()).hexdigest()
        return Hash


class MiscAdvancedUtils():
    @staticmethod
    def CRC_Burst(Course: str) -> None:
        from struct import pack
        from binascii import crc32
        with open(Course, "rb") as f:
            Binary = f.read()
        if(int(Binary[0:8].hex(), 16) != int("0x89504e470d0a1a0a", 16)):
            print("[CRC爆破]检测到[文件头错误]，请修改第[1-8]个字节为:89 50 4E 47 0D 0A 1A 0A")
        if(int(Binary[8:12].hex(), 16) != int("0x0000000d", 16)):
            print("[CRC爆破]检测到[数据块长度错误]，请修改第[9-12]个字节为:00 00 00 0D")
        if(int(Binary[12:16].hex(), 16) != int("0x49484452", 16)):
            print("[CRC爆破]检测到[数据块标识错误]，请修改第[13-16]个字节为:49 48 44 52")
        Code = crc32(Binary[12:29]) & 0xffffffff
        CRC = int(Binary[29:33].hex(), 16)
        if(Code == CRC):
            print("[CRC爆破]CRC校验码匹配")
        else:
            print("[CRC爆破]CRC校验码不匹配 即将进行[宽度]爆破")
            for i in range(1, 4097):
                temp = pack(">i", i)
                Code = crc32(bytes("IHDR", "ascii") + temp + Binary[20:29]) & 0xffffffff
                if(Code == CRC):
                    print("图片正确宽度为:{} Hex:{}".format(i, hex(i)))
                    return
            print("[CRC爆破][宽度]爆破失败 即将进行[高度]爆破")
            for i in range(1, 4097):
                temp = pack(">i", i)
                Code = crc32(bytes("IHDR", "ascii") + Binary[16:20] + temp + Binary[24:29]) & 0xffffffff
                if(Code == CRC):
                    print("图片正确高度为:{} Hex:{}".format(i, hex(i)))
                    return
            print("[CRC爆破][宽高单项爆破]失败 即将进行[宽高联合爆破]")
            for i in range(4097):
                width = pack(">i", i)
                for j in range(4097):
                    height = pack(">i", j)
                    Code = crc32(bytes("IHDR", "ascii") + width + height + Binary[24:29]) & 0xffffffff
                    if(Code == CRC):
                        print("[CRC爆破]宽度为:{} 高度为:{} Hex:{} {}".format(i, j, hex(i), hex(j)))
                        return
            print("[CRC爆破]爆破失败 请判断异常情况")

    @staticmethod
    def BinaryToQRCode(BinaryList: list) -> None:
        from PIL import Image
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

    @staticmethod
    def RGBToImage(RGBList: list, X: int, Y: int, Mode: str = "Column") -> None:
        from PIL import Image
        Board = Image.new("RGB", (X, Y))
        if Mode == "Column":
            for i in range(X):
                for j in range(Y):
                    Index = i * Y + j
                    Board.putpixel((i, j), tuple(RGBList[Index]))
        elif Mode == "Row":
            for i in range(Y):
                for j in range(X):
                    Index = i * X + j
                    Board.putpixel((j, i), tuple(RGBList[Index]))
        Board.save("RGBToImageResult.png")
        Board.show()

    @staticmethod
    def ImageToRGB(ImageCourse: str, Mode="Column") -> list:
        from PIL import Image
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

    @staticmethod
    def Request(Url: str, Method: str = "GET", Headers: dict = None, Params: dict = None, Data: dict = None) -> dict:
        from requests import request
        Response = request(Method, Url, headers=Headers, params=Params, data=Data)
        StatusCode = Response.status_code
        ResponseHeaders = Response.headers
        Cookies = Response.cookies
        Response.encoding = Response.apparent_encoding
        ResponseText = Response.text
        CompactResponseText = Response.text.replace("\n", "").replace(" ", "")
        Result = {"StatusCode": StatusCode, "ResponseHeaders": ResponseHeaders, "Cookies": Cookies, "ResponseText": ResponseText, "CompactResponseText": CompactResponseText}
        return Result
