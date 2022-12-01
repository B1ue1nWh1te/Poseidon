"""
本模块用于与 EVM 区块链网络进行交互，可满足大多数情况的需求。
"""

from web3 import Web3
from eth_account import Account as EthAccount
from loguru import logger
from sys import exc_info
from json import dumps


class Chain():
    """
    Chain 对象是进行链上交互的基础。
    """

    def __init__(self, RPCUrl: str, RequestParams: dict = None):
        """Chain 对象初始化函数。（当连接失败时会抛出异常）

        参数：
            RPCUrl (str): 要连接的链的 RPC 地址
            RequestParams (可选)(dict): 指定连接时使用的 request 参数，默认为 None。\n例如需要使用代理进行访问，则传入 {"proxies": {"http": "http://127.0.0.1:<ProxyPort>","https": "http://127.0.0.1:<ProxyPort>"}}

        成员变量：
            Net (Web3.HTTPProvider): web3py 实例化的链交互器对象
            ChainId (int): 链 ID
            ClientVersion (str): 所连接的 RPC 的 geth 等客户端软件的版本号
        """
        from web3 import HTTPProvider
        from web3.middleware import geth_poa_middleware
        from time import time
        StartTime = time()
        self.Net = Web3(HTTPProvider(RPCUrl, request_kwargs=RequestParams))
        if self.Net.isConnected():
            FinishTime = time()
            Delay = round((FinishTime - StartTime) * 1000)
            logger.success(f"\n[Chain][Connect]Successfully connected to [{RPCUrl}]. [Delay] {Delay} ms")
            self.Net.middleware_onion.inject(geth_poa_middleware, layer=0)
            self.GetBasicInformation()
        else:
            logger.error(f"\n[Chain][Connect]Failed to connect to [{RPCUrl}].")
            raise Exception("Failed to connect to chain.")

    def GetBasicInformation(self) -> dict:
        """获取链的基本信息。包括链 ID 、区块高度、当前 GasPrice(Gwei) 、所连接的 RPC 的 geth 等客户端软件的版本号。

        返回值：
            BasicInformation (dict): 链的基本信息构成的字典。
            {"ChainId"|"BlockNumber"|"GasPrice"|"ClientVersion"}
        """
        self.ChainId = self.Net.eth.chainId
        self.ClientVersion = self.Net.clientVersion
        BlockNumber = self.Net.eth.block_number
        GasPrice = Web3.fromWei(self.Net.eth.gas_price, "gwei")
        logger.success(f"\n[Chain][GetBasicInformation]\n[ChainId]{self.ChainId}\n[BlockNumber]{BlockNumber}\n[GasPrice]{GasPrice} Gwei\n[ClientVersion]{self.ClientVersion}")
        return {"ChainId": self.ChainId, "BlockNumber": BlockNumber, "GasPrice": GasPrice, "ClientVersion": self.ClientVersion}

    def GetTransactionInformationByHash(self, TransactionHash: str) -> dict:
        """根据交易哈希获取交易信息。包括交易类型（Traditional|EIP-1559）、交易所在区块号、发送者、接收者、(GasPrice 或 (MaxFeePerGas 和 MaxPriorityFeePerGas)(Gwei))、GasLimit、Nonce、Value、InputData。

        参数：
            TransactionHash (str): 要查询的交易的哈希

        返回值：
            TransactionInformation (dict): 交易数据构成的字典（当出现异常时返回 None ）
            {"TransactionHash"|"TransactionType"|"BlockNumber"|"From"|"To"|{"GasPrice"|("MaxFeePerGas"&"MaxPriorityFeePerGas")}|"GasLimit"|"Nonce"|"Value"|"InputData"}
        """
        try:
            Info = self.Net.eth.get_transaction(TransactionHash)
            BlockNumber = Info.blockNumber
            From = Info["from"]
            To = Info.to
            GasPrice = Info.gasPrice
            GasLimit = Info.gas
            Nonce = Info.nonce
            Value = Info.value
            InputData = Info.input
            if GasPrice != None:
                TransactionType = "Traditional"
                GasPrice = Web3.fromWei(GasPrice, "gwei")
                logger.success(
                    f"\n[Chain][GetTransactionByHash][{TransactionHash}]\n[TransactionType]{TransactionType}\n[BlockNumber]{BlockNumber}\n[From]{From}\n[To]{To}\n[GasPrice]{GasPrice} Gwei [GasLimit]{GasLimit}\n[Nonce]{Nonce} [Value]{Value}\n[InputData]{InputData}")
                return {"TransactionHash": TransactionHash, "TransactionType": TransactionType, "BlockNumber": BlockNumber, "From": From, "To": To, "GasPrice": GasPrice, "GasLimit": GasLimit, "Nonce": Nonce, "Value": Value, "InputData": InputData}
            else:
                TransactionType = "EIP-1559"
                MaxFeePerGas = Web3.fromWei(Info.maxFeePerGas, "gwei")
                MaxPriorityFeePerGas = Web3.fromWei(Info.maxPriorityFeePerGas, "gwei")
                logger.success(
                    f"\n[Chain][GetTransactionByHash][{TransactionHash}]\n[TransactionType]{TransactionType}\n[BlockNumber]{BlockNumber}\n[From]{From}\n[To]{To}\n[MaxFeePerGas]{MaxFeePerGas} Gwei\n[MaxPriorityFeePerGas]{MaxPriorityFeePerGas} Gwei\n[GasLimit]{GasLimit} [Nonce]{Nonce} [Value]{Value}\n[InputData]{InputData}")
                return {"TransactionHash": TransactionHash, "TransactionType": TransactionType, "BlockNumber": BlockNumber, "From": From, "To": To, "MaxFeePerGas": MaxFeePerGas, "MaxPriorityFeePerGas": MaxPriorityFeePerGas, "GasLimit": GasLimit, "Nonce": Nonce, "Value": Value, "InputData": InputData}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Chain][GetTransactionByHash][{TransactionHash}]\nFailed to get transaction [{TransactionHash}] information.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def GetBalance(self, Address: str) -> int:
        """根据账户地址获取其主币余额。

        参数：
            Address (str): 账户地址

        返回值：
            Balance (int): 账户主币余额（单位为wei 当出现异常时返回 None ）
        """
        try:
            Address = Web3.toChecksumAddress(Address)
            Balance = self.Net.eth.get_balance(Address)
            logger.success(f"\n[Chain][GetBalance][{Address}]\n[{Balance} Wei]<=>[{Web3.fromWei(Balance,'ether')} Ether]")
            return Balance
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Chain][GetBalance][{Address}]\nFailed to get [{Address}] balance.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def GetCode(self, Address: str) -> str:
        """根据合约地址获取其字节码。

        参数：
            Address (str): 合约地址

        返回值：
            Code (str): 合约字节码（十六进制形式 含 0x 前缀 当出现异常时返回 None ）
        """
        try:
            Address = Web3.toChecksumAddress(Address)
            Code = self.Net.eth.get_code(Address).hex()
            logger.success(f"\n[Chain][GetCode][{Address}]\n[Code]{Code}")
            return Code
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Chain][GetCode][{Address}]\nFailed to get [{Address}] code.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def GetStorage(self, Address: str, Index: int) -> str:
        """根据合约地址和存储插槽索引获取存储值。

        参数：
            Address (str): 合约地址
            Index (int): 存储插槽索引

        返回值：
            Data (str): 存储值（十六进制形式 含 0x 前缀 当出现异常时返回 None ）
        """
        try:
            Address = Web3.toChecksumAddress(Address)
            Data = self.Net.eth.get_storage_at(Address, Index).hex()
            logger.success(f"\n[Chain][GetStorage][{Address}][{Index}]\n[Hex][{Data}]<=>[Dec][{int(Data,16)}]")
            return Data
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Chain][GetStorage][{Address}][{Index}]\nFailed to get [{Address}][{Index}] storage.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def DumpStorage(self, Address: str, Count: int) -> list:
        """根据合约地址和数量批量遍历存储插槽并获取值（从插槽 0 开始）。

        参数：
            Address (str): 合约地址
            Count (int): 要获取的数量

        返回值：
            Data (List[str]): 存储值列表（十六进制形式 含 0x 前缀 当出现异常时返回 None ）
        """
        try:
            Address = Web3.toChecksumAddress(Address)
            Data = [self.Net.eth.get_storage_at(Address, i).hex() for i in range(Count)]
            Temp = '\n'.join(Data)
            logger.success(f"\n[Chain][DumpStorage][{Address}][slot 0 ... {Count-1}]\n{Temp}")
            return Data
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Chain][DumpStorage][{Address}][slot 0 ... {Count-1}]\nFailed to dump [{Address}][slot 0 ... {Count-1}] storages.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def GetPublicKeyByTransactionHash(self, TransactionHash: str) -> tuple:
        """通过一笔已在链上确认的交易的哈希，获取账户的公钥。

        参数：
            TransactionHash (str): 交易哈希

        返回值：
            (Address, PublicKey) (tuple): 由账户地址和账户公钥组成的元组（当出现异常时返回 None ）
        """
        try:
            from eth_account._utils.signing import to_standard_v, extract_chain_id, serializable_unsigned_transaction_from_dict
            Transaction = self.Net.eth.get_transaction(TransactionHash)
            Signature = self.Net.eth.account._keys.Signature(vrs=(to_standard_v(extract_chain_id(Transaction.v)[1]), Web3.toInt(Transaction.r), Web3.toInt(Transaction.s)))
            UnsignedTransactionDict = {i: Transaction[i] for i in ['chainId', 'nonce', 'gasPrice' if int(
                Transaction.type, 0) != 2 else '', 'gas', 'to', 'value', 'accessList', 'maxFeePerGas', 'maxPriorityFeePerGas'] if i in Transaction}
            UnsignedTransactionDict['data'] = Transaction['input']
            UnsignedTransaction = serializable_unsigned_transaction_from_dict(UnsignedTransactionDict)
            Temp = Signature.recover_public_key_from_msg_hash(UnsignedTransaction.hash())
            PublicKey = str(Temp).replace('0x', '0x04')  # 比特币未压缩公钥格式
            Address = Temp.to_checksum_address()
            logger.success(
                f"\n[Chain][GetPublicKeyByTransactionHash]\n[TransactionHash]{TransactionHash}\n[Address]{Address}\n[PublicKey]{PublicKey}")
            return (Address, PublicKey)
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Chain][GetPublicKeyByTransactionHash]\n[TransactionHash]{TransactionHash}\nFailed to get public key by transaction hash.\n[ExceptionInformation]{ExceptionInformation}")
            return None


class Account():
    """
    Account 对象是发起链上调用的基础。
    """

    def __init__(self, Chain: Chain, PrivateKey: str):
        """通过私钥导入账户并与 Chain 对象绑定，后续的所有链上调用都会发送至 Chain 所表示的链上。（当导入失败时将会抛出异常）

        参数：
            Chain (Poseidon.Blockchain.Chain): 链对象
            PrivateKey (str): 账户私钥（十六进制形式 不含 0x 前缀）

        成员变量：
            Chain (Poseidon.Blockchain.Chain): 链对象
            Address (str): 账户地址
            PrivateKey (str): 账户私钥
        """

        try:
            self.Chain = Chain
            self.Net = Chain.Net
            Temp = EthAccount.from_key(PrivateKey)
            self.Address = Web3.toChecksumAddress(Temp.address)
            self.PrivateKey = Temp.privateKey
            self.Net.eth.default_account = self.Address
            logger.success(f"\n[Account][Import]Successfully import account [{self.Address}].")
            self.GetSelfBalance()
        except:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Account][Import]Failed to import account.\n[ExceptionInformation]{ExceptionInformation}")
            raise Exception("Failed to import account.")

    def GetSelfBalance(self) -> int:
        """获取自身账户的主币余额。（当余额为 0 时会输出无法发送交易的警告）

        返回值：
            Balance (int): 账户主币余额（单位为wei 当出现异常时返回 None ）
        """
        Balance = self.Chain.GetBalance(self.Address)
        if Balance == 0:
            logger.warning(f"\n[Account][GetSelfBalance]Warning: This account's balance is insufficient to pay transactions fee.")
        return Balance

    def Transfer(self, To: str, Value: int, Data: str = "0x") -> dict:
        """向指定账户转账指定数量的主币，可附带信息。（GasLimit 为 100000，若 90 秒内交易未确认则作超时处理）

        参数：
            To (str): 接收方地址
            Value (int): 发送的主币数量（单位为 wei ）
            Data (可选)(str): 交易数据（十六进制形式 含 0x 前缀），默认值为 "0x"

        返回值：
            TransactionInformation (dict): 交易回执信息构成的字典（当交易失败时返回{"Status"|"TransactionHash"} 当出现异常时返回 None ）\n
            {"Status"|"TransactionHash"|"BlockNumber"|"From"|"To"|"Value"|"GasUsed"|"Data"|"Logs"}
        """
        try:
            From = Web3.toChecksumAddress(self.Address)
            To = Web3.toChecksumAddress(To)
            Txn = {
                "chainId": self.Chain.ChainId,
                "from": From,
                "to": To,
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "value": Value,
                "gasPrice": self.Net.eth.gas_price,
                "gas": 100000,
                "data": Data,
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            Txn["gasPrice"] = f'{Web3.fromWei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][Transfer]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}")
            TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=90)
            Status = TransactionReceipt.status
            if Status:
                BlockNumber = TransactionReceipt.blockNumber
                GasUsed = TransactionReceipt.gasUsed
                Logs = TransactionReceipt.logs
                logger.success(
                    f"\n[Account][Transfer][Success]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[From]{From}\n[To]{To}\n[Value]{Value} [GasUsed]{GasUsed}\n[Data]{Data}\n[Logs]{Logs}")
                return {"Status": Status, "TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "From": From, "To": To, "Value": Value, "GasUsed": GasUsed, "Data": Data, "Logs": Logs}
            else:
                logger.error(f"\n[Account][Transfer][Fail]\n[TransactionHash]{TransactionHash}")
                return {"Status": Status, "TransactionHash": TransactionHash}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Account][Transfer][Error]\n[From]{From}\n[To]{To}\n[Value]{Value}\n[Data]{Data}\nFailed to transfer to [{To}].\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def SendTransaction(self, To: str, Data: str, Value: int = 0, GasLimit: int = 1000000) -> dict:
        """发送一笔自定义交易（传统方式）。（若 90 秒内交易未确认则作超时处理）

        参数：
            To (str): 交易接收方地址
            Data (str): 交易数据（十六进制形式 含 0x 前缀）
            Value (可选)(int): 随交易发送的主币数量（单位为 wei ），默认为 0 wei
            GasLimit (可选)(int): Gas最大使用量（单位为 wei ），默认为 1000000 wei

        返回值：
            TransactionInformation (dict): 交易回执信息构成的字典（当交易失败时返回{"Status"|"TransactionHash"} 当出现异常时返回 None ）\n
            {"Status"|"TransactionHash"|"BlockNumber"|"From"|"To"|"Value"|"GasUsed"|"Data"|"Logs"}
        """
        try:
            From = Web3.toChecksumAddress(self.Address)
            To = Web3.toChecksumAddress(To)
            Txn = {
                "chainId": self.Chain.ChainId,
                "from": From,
                "to": To,
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "value": Value,
                "gasPrice": self.Net.eth.gas_price,
                "gas": GasLimit,
                "data": Data,
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            Txn["gasPrice"] = f'{Web3.fromWei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][SendTransaction][Traditional]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}")
            TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=90)
            Status = TransactionReceipt.status
            if Status:
                BlockNumber = TransactionReceipt.blockNumber
                GasUsed = TransactionReceipt.gasUsed
                Logs = TransactionReceipt.logs
                logger.success(
                    f"\n[Account][SendTransaction][Traditional][Success]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[From]{From}\n[To]{To}\n[Value]{Value} [GasUsed]{GasUsed}\n[Data]{Data}\n[Logs]{Logs}")
                return {"Status": Status, "TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "From": From, "To": To, "Value": Value, "GasUsed": GasUsed, "Data": Data, "Logs": Logs}
            else:
                logger.error(f"\n[Account][SendTransaction][Traditional][Fail]\n[TransactionHash]{TransactionHash}")
                return {"Status": Status, "TransactionHash": TransactionHash}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Account][SendTransaction][Traditional][Error]Failed to send transaction.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def SendTransactionByEIP1559(self, To: str, Data: str, Value: int = 0, GasLimit: int = 1000000) -> dict:
        """发送一笔自定义交易（EIP-1559方式）。（若 90 秒内交易未确认则作超时处理）

        参数：
            To (str): 交易接收方地址
            Data (str): 交易数据（十六进制形式 含 0x 前缀）
            Value (可选)(int): 随交易发送的主币数量（单位为 wei ），默认为 0 wei
            GasLimit (可选)(int): Gas最大使用量（单位为 wei ），默认为 1000000 wei

        返回值：
            TransactionInformation (dict): 交易回执信息构成的字典（当交易失败时返回{"Status"|"TransactionHash"} 当出现异常时返回 None ）\n
            {"Status"|"TransactionHash"|"BlockNumber"|"From"|"To"|"Value"|"GasUsed"|"Data"|"Logs"}
        """
        try:
            From = Web3.toChecksumAddress(self.Address)
            To = Web3.toChecksumAddress(To)
            BaseFee = self.Net.eth.gas_price
            MaxPriorityFee = Web3.toWei(1, "gwei") + self.Net.eth.max_priority_fee
            Txn = {
                "chainId": self.Chain.ChainId,
                "from": From,
                "to": To,
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "value": Value,
                "maxFeePerGas": BaseFee + MaxPriorityFee,
                "maxPriorityFeePerGas": MaxPriorityFee,
                "gas": GasLimit,
                "data": Data
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            logger.info(f"\n[Account][SendTransaction][EIP-1559]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}")
            TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=90)
            Status = TransactionReceipt.status
            if Status:
                BlockNumber = TransactionReceipt.blockNumber
                GasUsed = TransactionReceipt.gasUsed
                Logs = TransactionReceipt.logs
                logger.success(
                    f"\n[Account][SendTransaction][EIP-1559][Success]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[From]{From}\n[To]{To}\n[Value]{Value} [GasUsed]{GasUsed}\n[Data]{Data}\n[Logs]{Logs}")
                return {"Status": Status, "TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "From": From, "To": To, "Value": Value, "GasUsed": GasUsed, "Data": Data, "Logs": Logs}
            else:
                logger.error(f"\n[Account][SendTransaction][EIP-1559][Fail]\n[TransactionHash]{TransactionHash}")
                return {"Status": Status, "TransactionHash": TransactionHash}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Account][SendTransaction][EIP-1559][Error]Failed to send transaction.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def DeployContract(self, ABI: dict, Bytecode: str, Value: int = 0, *Arguments) -> dict:
        """部署合约。（若 90 秒内交易未确认则作超时处理）

        参数：
            ABI (dict): 合约 ABI
            Bytecode (str): 合约字节码（十六进制形式 含 0x 前缀）
            Value (可选)(int): 随交易发送给合约的主币数量（单位为 wei ），默认为 0 wei
            *Arguments (可选)(any): 传给合约构造函数的参数，默认为空

        返回值：
            TransactionInformation (dict): 交易回执信息构成的字典（其中"Contract"为已实例化的 Contract 对象 当交易失败时返回{"Status"|"TransactionHash"} 当出现异常时返回 None ）\n
            {"Status"|"TransactionHash"|"BlockNumber"|"ContractAddress"|"Value"|"GasUsed"|"Logs"|"Contract"}
        """
        try:
            DeployingContract = self.Net.eth.contract(abi=ABI, bytecode=Bytecode)
            TransactionData = DeployingContract.constructor(*Arguments).buildTransaction({"value": Value})
            From = Web3.toChecksumAddress(self.Address)
            Txn = {
                "chainId": self.Chain.ChainId,
                "from": From,
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "value": TransactionData["value"],
                "gasPrice": self.Net.eth.gas_price,
                "gas": TransactionData["gas"],
                "data": TransactionData["data"]
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            logger.info(f"\n[Account][DeployContract]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}")
            TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=90)
            Status = TransactionReceipt.status
            if Status:
                ContractAddress = TransactionReceipt.contractAddress
                BlockNumber = TransactionReceipt.blockNumber
                GasUsed = TransactionReceipt.gasUsed
                Logs = TransactionReceipt.logs
                DeployedContract = Contract(self, ContractAddress, ABI)
                logger.success(
                    f"\n[Account][DeployContract][Success]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[ContractAddress]{ContractAddress}\n[Value]{Value} [GasUsed]{GasUsed}\n[Logs]{Logs}")
                return {"Status": Status, "TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "ContractAddress": ContractAddress, "Value": Value, "GasUsed": GasUsed, "Logs": Logs, "Contract": DeployedContract}
            else:
                logger.error(f"\n[Account][DeployContract][Fail]\n[TransactionHash]{TransactionHash}")
                return {"Status": Status, "TransactionHash": TransactionHash}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Account][DeployContract][Error]Failed to deploy contract.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def DeployContractWithoutABI(self, Bytecode: str, Value: int = 0, GasLimit: int = 10000000) -> dict:
        """在没有 ABI 的情况下，仅使用字节码来部署合约。（若 90 秒内交易未确认则作超时处理）

        参数：
            Bytecode (str): 合约字节码（十六进制形式 含 0x 前缀）
            Value (可选)(int): 随交易发送给合约的主币数量（单位为 wei ），默认为 0 wei
            GasLimit (可选)(int): Gas最大使用量（单位为 wei ），默认为 10000000 wei

        返回值：
            TransactionInformation (dict): 交易回执信息构成的字典（当交易失败时返回{"Status"|"TransactionHash"} 当出现异常时返回 None ）\n
            {"Status"|"TransactionHash"|"BlockNumber"|"ContractAddress"|"Value"|"GasUsed"|"Logs"}
        """
        try:
            From = Web3.toChecksumAddress(self.Address)
            Txn = {
                "chainId": self.Chain.ChainId,
                "from": From,
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "value": Value,
                "gasPrice": self.Net.eth.gas_price,
                "gas": GasLimit,
                "data": Bytecode,
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            logger.info(f"\n[Account][DeployContractWithoutABI]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}")
            TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=90)
            Status = TransactionReceipt.status
            if Status:
                ContractAddress = TransactionReceipt.contractAddress
                BlockNumber = TransactionReceipt.blockNumber
                GasUsed = TransactionReceipt.gasUsed
                Logs = TransactionReceipt.logs
                logger.success(
                    f"\n[Account][DeployContractWithoutABI][Success]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[ContractAddress]{ContractAddress}\n[Value]{Value} [GasUsed]{GasUsed}\n[Logs]{Logs}")
                return {"Status": Status, "TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "ContractAddress": ContractAddress, "Value": Value, "GasUsed": GasUsed, "Logs": Logs}
            else:
                logger.error(f"\n[Account][DeployContractWithoutABI][Fail]\n[TransactionHash]{TransactionHash}")
                return {"Status": Status, "TransactionHash": TransactionHash}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Account][DeployContractWithoutABI][Error]Failed to deploy contract.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def SignMessage(self, Message: str) -> dict:
        """对消息字符串进行签名。

        参数：
            Message (str): 待签名消息字符串

        返回值：
            SignatureData (str): 签名数据构成的字典（当出现异常时返回 None ）\n
            {"Address"|"Message"|"MessageHash"|"Signature"|"R"|"S"|"V"}
        """
        from eth_account.messages import encode_defunct
        try:
            Temp = encode_defunct(text=Message)
            SignedMessage = EthAccount.sign_message(Temp, private_key=self.PrivateKey)
            MessageHash = SignedMessage.messageHash.hex()
            Signature = SignedMessage.signature.hex()
            R = hex(SignedMessage.r)
            S = hex(SignedMessage.s)
            V = hex(SignedMessage.v)
            logger.success(
                f"\n[Account][SignMessage]\n[Address]{self.Address}\n[Message]{Message}\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[R]{R}\n[S]{S}\n[V]{V}")
            return {"Address": self.Address, "Message": Message, "MessageHash": MessageHash, "Signature": Signature, "R": R, "S": S, "V": V}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Account][SignMessage]\n[Address]{self.Address}\n[Message]{Message}\nFailed to sign message.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def SignMessageHash(self, MessageHash: str) -> dict:
        """对消息哈希进行签名。

        参数：
            MessageHash (str): 待签名消息哈希

        返回值：
            SignatureData (str): 签名数据构成的字典（当出现异常时返回 None ）\n
            {"Address"|"MessageHash"|"Signature"|"R"|"S"|"V"}
        """
        try:
            SignedMessage = EthAccount.signHash(MessageHash, self.PrivateKey)
            Signature = SignedMessage.signature.hex()
            R = hex(SignedMessage.r)
            S = hex(SignedMessage.s)
            V = hex(SignedMessage.v)
            logger.success(
                f"\n[Account][SignMessageHash]\n[Address]{self.Address}\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[R]{R}\n[S]{S}\n[V]{V}")
            return {"Address": self.Address, "MessageHash": MessageHash, "Signature": Signature, "R": R, "S": S, "V": V}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Account][SignMessageHash]\n[Address]{self.Address}\n[MessageHash]{MessageHash}\nFailed to sign message hash.\n[ExceptionInformation]{ExceptionInformation}")
            return None


class Contract():
    """
    Contract 对象是与指定合约进行交互的基础。
    """

    def __init__(self, Account: Account, Address: str, ABI: dict):
        """通过合约地址与 ABI 实例化合约对象，并与 Account 对象绑定，后续的所有对该合约的调用都会由这一账户发起。（当实例化失败时会抛出异常）

        参数：
            Account (Poseidon.Blockchain.Account): 账户对象
            Address (str): 合约地址
            ABI (str): 合约 ABI

        成员变量：
            Account (Poseidon.Blockchain.Account): 账户对象
            Address (str): 合约地址
            Instance (Web3.eth.Contract): web3py 原生 contract 对象实例
        """
        try:
            self.Account = Account
            self.Net = Account.Net
            self.Address = Web3.toChecksumAddress(Address)
            self.Instance = self.Net.eth.contract(address=self.Address, abi=ABI)
            logger.success(f"\n[Contract][Instantiate]Successfully instantiated contract [{self.Address}].")
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Contract][Instantiate]Failed to instantiated contract [{self.Address}].\n[ExceptionInformation]{ExceptionInformation}")
            raise Exception("Failed to instantiate contract.")

    def CallFunction(self, FunctionName: str, *FunctionArguments) -> dict:
        """通过传入函数名及参数来调用该合约内的函数。

        参数：
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(any): 函数参数，默认为空

        返回值：
            TransactionResult (dict): 交易回执信息构成的字典（当交易失败时返回{"Status"|"TransactionHash"} 当出现异常时返回 None ）\n
            {"Status"|"TransactionHash"|"BlockNumber"|"From"|"To"|"Value"|"GasUsed"|"Data"|"Logs"}
        """
        TransactionData = self.Instance.functions[FunctionName](*FunctionArguments).buildTransaction()
        logger.info(f"\n[Contract][CallFunction]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}")
        TransactionResult = self.Account.SendTransaction(self.Address, TransactionData["data"], TransactionData["value"], TransactionData["gas"])
        return TransactionResult

    def CallFunctionWithValueAndGasLimit(self, Value: int, GasLimit: int, FunctionName: str, *FunctionArguments) -> dict:
        """通过传入函数名及参数来调用该合约内的函数（支持自定义 Value 和 GasLimit）。

        参数：
            Value (int): 随交易发送的主币数量（单位为 wei ）
            GasLimit (int): 该交易最多可消耗的 Gas 量（单位为 wei ）
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(any): 函数参数，默认为空

        返回值：
            TransactionResult (dict): 交易回执信息构成的字典（当交易失败时返回{"Status"|"TransactionHash"} 当出现异常时返回 None ）\n
            {"Status"|"TransactionHash"|"BlockNumber"|"From"|"To"|"Value"|"GasUsed"|"Data"|"Logs"}
        """
        TransactionData = self.Instance.functions[FunctionName](*FunctionArguments).buildTransaction({"value": Value, "gas": GasLimit})
        logger.info(
            f"\n[Contract][CallFunctionWithValueAndGasLimit]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[Value]{TransactionData['value']} [Gas]{TransactionData['gas']}")
        TransactionResult = self.Account.SendTransaction(self.Address, TransactionData["data"], TransactionData["value"], TransactionData["gas"])
        return TransactionResult

    def ReadOnlyCallFunction(self, FunctionName: str, *FunctionArguments):
        """通过传入函数名及参数来调用该合约内的只读函数。

        参数：
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(any): 函数参数，默认为空

        返回值：
            Result (any): 调用函数后得到的返回值（当出现异常时返回 None ）
        """
        try:
            Result = self.Instance.functions[FunctionName](*FunctionArguments).call()
            logger.success(f"\n[Contract][ReadOnlyCallFunction]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[Result]{Result}")
            return Result
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Contract][ReadOnlyCallFunction]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\nFailed to call readonly function.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def EncodeABI(self, FunctionName: str, *FunctionArguments) -> str:
        """通过传入函数名及参数进行编码，相当于生成调用该函数的 CallData 。

        参数：
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(any): 函数参数，默认为空

        返回值：
            CallData (str): 调用数据编码（十六进制形式 含 0x 前缀 当出现异常时返回 None ）
        """
        try:
            CallData = self.Instance.encodeABI(fn_name=FunctionName, args=FunctionArguments)
            logger.success(f"\n[Contract][EncodeABI]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[CallData]{CallData}")
            return CallData
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Contract][EncodeABI]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\nFailed to encode abi.\n[ExceptionInformation]{ExceptionInformation}")
            return None


class BlockchainUtils():
    """
    通用工具，链下使用的功能。
    """

    @staticmethod
    def SwitchSolidityVersion(SolidityVersion: str):
        """设置当前使用的 Solidity 版本，若该版本未安装则会自动安装。（当设置版本失败时会抛出异常）

        参数：
            SolidityVersion (str): Solidity 版本号
        """
        from solcx import install_solc, set_solc_version
        try:
            install_solc(SolidityVersion)
            set_solc_version(SolidityVersion)
            logger.success(f"\n[BlockchainUtils][SwitchSolidityVersion]Current Version: {SolidityVersion}")
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[BlockchainUtils][SwitchSolidityVersion]Failed to switch to version [{SolidityVersion}].\n[ExceptionInformation]{ExceptionInformation}")
            raise Exception("Failed to switch solidity version.")

    @staticmethod
    def Compile(FileCourse: str, ContractName: str, SolidityVersion: str = None, AllowPaths: str = None, Optimize: bool = False) -> tuple:
        """根据给定的参数使用 py-solc-x 编译合约。（当编译失败时会抛出异常）

        参数：
            FileCourse (str): 合约文件完整路径（当合约文件与脚本文件在同一目录下时可直接使用文件名）
            ContractName (str): 要编译的合约名称
            SolidityVersion (可选)(str): 指定使用的 Solidity 版本（若不指定则会使用当前已激活的 Solidity 版本进行编译），默认为 None
            AllowPaths (可选)(str): 指定路径白名单（在编译时可能会出现 AllowPaths 相关错误，可在这里解决），默认为 None
            Optimize (可选)(str): 是否开启优化器，False 为关闭，True 为开启，默认为 False

        返回值：
            (ABI, Bytecode) (tuple): 由 ABI 和 Bytecode 组成的元组
        """
        from solcx import compile_source
        from json import dump
        try:
            with open(FileCourse, "r", encoding="utf-8") as sol:
                CompiledSol = compile_source(sol.read(), solc_version=SolidityVersion, allow_paths=AllowPaths, optimize=Optimize, output_values=['abi', 'bin'])
            ContractData = CompiledSol[f'<stdin>:{ContractName}']
            ABI = ContractData['abi']
            Bytecode = ContractData['bin']
            with open(f'{ContractName}_ABI.json', 'w') as f:
                dump(ABI, f, indent=4)
            logger.success(f"\n[BlockchainUtils][Compile]\n[FileCourse]{FileCourse}\n[ContractName]{ContractName}\n[ABI]{ABI}\n[Bytecode]{Bytecode}")
            return (ABI, Bytecode)
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][Compile]\n[FileCourse]{FileCourse}\n[ContractName]{ContractName}\nFailed to compile the contract.\n[ExceptionInformation]{ExceptionInformation}")
            raise Exception("Failed to compile the contract.")

    @staticmethod
    def CreateNewAccount() -> tuple:
        """创建新账户。

        返回值：
            (Address, PrivateKey) (tuple): 由账户地址和私钥组成的元组
        """
        Temp = EthAccount.create()
        Address = Web3.toChecksumAddress(Temp.address)
        PrivateKey = Temp.privateKey.hex()
        logger.success(f"\n[BlockchainUtils][CreateNewAccount]\n[Address]{Address}\n[PrivateKey]{PrivateKey}")
        return (Address, PrivateKey)

    @staticmethod
    def MnemonicToAddressAndPrivateKey(Mnemonic: str) -> tuple:
        """将助记词转换为账户地址与私钥（参考 BIP-39 标准）。

        参数：
            Mnemonic (str): 助记词以空格进行分隔而组成的字符串

        返回值：
            (Address, PrivateKey) (tuple): 由账户地址和私钥组成的元组（当出现异常时返回 None ）
        """
        try:
            EthAccount.enable_unaudited_hdwallet_features()
            Temp = EthAccount.from_mnemonic(Mnemonic)
            Address = Web3.toChecksumAddress(Temp.address)
            PrivateKey = Temp.privateKey.hex()
            logger.success(f"\n[BlockchainUtils][MnemonicToAddressAndPrivateKey]\n[Mnemonic]{Mnemonic}\n[Address]{Address}\n[PrivateKey]{PrivateKey}")
            return (Address, PrivateKey)
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][MnemonicToAddressAndPrivateKey]\n[Mnemonic]{Mnemonic}\nFailed to convert mnemonic to address and private key.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    @staticmethod
    def RecoverMessage(Message: str, Signature: str) -> str:
        """通过消息原文和签名还原出签署者的账户地址。

        参数：
            Message (str): 消息原文
            Signature (str): 签名

        返回值：
            Signer (str): 签署者的账户地址（当出现异常时返回 None ）
        """
        from eth_account.messages import encode_defunct
        try:
            Temp = encode_defunct(text=Message)
            Signer = EthAccount.recover_message(Temp, signature=Signature)
            logger.success(f"\n[BlockchainUtils][RecoverMessage]\n[Message]{Message}\n[Signature]{Signature}\n[Signer]{Signer}")
            return Signer
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][RecoverMessage]\n[Message]{Message}\n[Signature]{Signature}\nFailed to recover message.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    @staticmethod
    def RecoverMessageHash(MessageHash: str, Signature: str) -> str:
        """通过消息哈希和签名还原出签署者的账户地址。

        参数：
            MessageHash (str): 消息哈希
            Signature (str): 签名

        返回值：
            Signer (str): 签署者的账户地址（当出现异常时返回 None ）
        """
        try:
            Signer = EthAccount.recoverHash(MessageHash, signature=Signature)
            logger.success(f"\n[BlockchainUtils][RecoverMessageByHash]\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[Signer]{Signer}")
            return Signer
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][RecoverMessageByHash]\n[MessageHash]{MessageHash}\n[Signature]{Signature}\nFailed to recover message hash.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    @staticmethod
    def RecoverRawTransaction(RawTransactionData: str) -> str:
        """用于获取签署此交易的账户的地址。

        参数：
            RawTransactionData (str): 原生交易数据（十六进制形式 含 0x 前缀）

        返回值：
            Address (str): 账户地址（当出现异常时返回 None ）
        """
        try:
            Address = EthAccount.recover_transaction(RawTransactionData)
            logger.success(f"\n[BlockchainUtils][RecoverRawTransaction]\n[RawTransactionData]{RawTransactionData}\n[Address]{Address}")
            return Address
        except:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][RecoverRawTransaction]\n[RawTransactionData]{RawTransactionData}\nFailed to recover raw transaction.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    @staticmethod
    def CrackSelector(TargetFunctionName: str, TargetFunctionParameters: list, GenerateFunctionParameters: list) -> str:
        """根据目标函数名与参数以及要生成的函数的参数，爆破出一个函数名，以使得这两个函数的 Selector 相等。（现在还是单线程，非常非常慢，之后有时间了再进行优化）

        参数：
            TargetFunctionName (str): 目标函数名
            TargetFunctionParameters (List[str]): 目标函数参数列表
            GenerateFunctionParameters (List[str]): 要生成的函数的参数列表

        返回值：
            GenerateFunction (str): 爆破出的函数的完整表示（当出现异常时返回 None ）
        """
        def Crack(TargetFunctionSelector: str, GenerateFunctionParameters: list) -> str:
            import random
            Charset = "0123456789abcdef"
            Temp1 = ','.join(GenerateFunctionParameters)
            s = 0
            while True:
                Temp2 = ''.join(random.choices(Charset, k=12))
                s += 1
                print(s, end="\r")
                if Web3.keccak(f"{Temp2}({Temp1})".encode())[:4].hex() == TargetFunctionSelector:
                    return f"{Temp2}({Temp1})"
        try:
            TargetFunctionSelector = Web3.keccak(f"{TargetFunctionName}({','.join(TargetFunctionParameters)})".encode())[:4].hex()
            logger.info(
                f"[BlockchainUtils][SelectorCrack]\n[TargetFunction]{TargetFunctionName}({','.join(TargetFunctionParameters)})\n[GenerateFunction]???({','.join(GenerateFunctionParameters)})\nCrack start...")
            GenerateFunction = Crack(TargetFunctionSelector, GenerateFunctionParameters)
            logger.success(f"\n[BlockchainUtils][SelectorCrack][Success]\n[GenerateFunction]{GenerateFunction}")
            return GenerateFunction
        except:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][SelectorCrack][Fail]Failed to crack selector.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    @staticmethod
    def AssemblyToBytecode(Assembly: str) -> str:
        """将 EVM Assembly 转为 EVM Bytecode 。

        参数：
            Assembly (str): EVM Assembly 字符串

        返回值：
            Bytecode (str): EVM Bytecode（十六进制形式 含 0x 前缀 当出现异常时返回 None ）
        """
        try:
            from pyevmasm import assemble_hex
            Bytecode = assemble_hex(Assembly)
            logger.success(f"\n[BlockchainUtils][AssemblyToBytecode][Success]\n[Bytecode]{Bytecode}")
            return Bytecode
        except:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][AssemblyToBytecod][Fail]Failed to transform assembly to bytecode.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    @staticmethod
    def BytecodeToAssembly(Bytecode: str) -> str:
        """将 EVM Bytecode 转为 EVM Assembly 。

        参数：
            Bytecode (str): EVM Bytecode 字符串（十六进制形式 含 0x 前缀）

        返回值：
            Assembly (str): EVM Assembly（当出现异常时返回 None ）
        """
        try:
            from pyevmasm import disassemble_hex
            Assembly = disassemble_hex(Bytecode)
            logger.success(f"\n[BlockchainUtils][AssemblyToBytecode][Success]\n[Assembly]\n{Assembly}")
            return Assembly
        except:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][BytecodeToAssembly][Fail]Failed to transform bytecode to assembly.\n[ExceptionInformation]{ExceptionInformation}")
            return None
