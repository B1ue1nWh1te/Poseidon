"""
本模块可用于与任何以太坊同构链（即通常所说的 EVM 兼容链）进行交互，支持常用的链上交互操作。
"""

from web3 import Web3
from eth_account import Account as EthAccount
from loguru import logger
from sys import exc_info
from json import dumps

logger.add('logs\\Poseidon_{time}.log')


class Chain():
    """
    Chain 是区块链实例，作为链上交互的基础。
    """

    def __init__(self, RPCUrl: str, RequestParams: dict = None):
        """
        初始化。当连接失败时会抛出异常。

        参数：
            RPCUrl (str): 链 RPC 地址
            RequestParams (可选)(dict): 指定连接时使用的 request 参数，默认为 None。
            例如当需要使用代理进行访问时，则传入 RequestParams={"proxies": {"http": "http://127.0.0.1:<ProxyPort>","https": "http://127.0.0.1:<ProxyPort>"}}

        成员变量：
            Net (Web3.HTTPProvider): web3.py 原生的链交互器对象
            ChainId (int): 链 ID
            ClientVersion (str): 链 RPC 的客户端软件版本号
        """
        from web3 import HTTPProvider
        from web3.middleware import geth_poa_middleware
        from time import time
        RequestParamsPrint = f"[RequestParams]{RequestParams}\n" if RequestParams else ""
        StartTime = time()
        self.Net = Web3(HTTPProvider(RPCUrl, request_kwargs=RequestParams))
        if self.Net.isConnected():
            FinishTime = time()
            Delay = round((FinishTime - StartTime) * 1000)
            logger.success(f"\n[Chain][Initialize]Connected to [{RPCUrl}] [{Delay} ms]\n{RequestParamsPrint}{'-'*80}")
            self.Net.middleware_onion.inject(geth_poa_middleware, layer=0)
            self.GetBasicInformation()
        else:
            logger.error(f"\n[Chain][Initialize]Failed to connect to [{RPCUrl}]\n{RequestParamsPrint}{'-'*80}")
            raise Exception("Failed to connect to chain.")

    def GetBasicInformation(self) -> dict:
        """
        获取链的基本信息。包括链 ID 、区块高度、 GasPrice 、出块间隔、链 RPC 的客户端软件版本号。

        返回值：
            BasicInformation (dict): 链的基本信息构成的字典。
            {"ChainId"|"BlockNumber"|"GasPrice"|"Timeslot"|"ClientVersion"}
        """
        self.ChainId = self.Net.eth.chain_id
        self.ClientVersion = self.Net.clientVersion
        BlockNumber = self.Net.eth.block_number
        GasPrice = self.Net.eth.gas_price
        Timeslot = self.Net.eth.get_block(BlockNumber).timestamp - self.Net.eth.get_block(BlockNumber - 1).timestamp
        logger.success(
            f"\n[Chain][GetBasicInformation]\n[ChainId]{self.ChainId}\n[BlockNumber]{BlockNumber}\n[GasPrice]{Web3.fromWei(GasPrice, 'gwei')} Gwei\n[Timeslot]{Timeslot}s\n[ClientVersion]{self.ClientVersion}\n{'-'*80}")
        return {"ChainId": self.ChainId, "BlockNumber": BlockNumber, "GasPrice": GasPrice, "Timeslot": Timeslot, "ClientVersion": self.ClientVersion}

    def GetTransactionInformationByHash(self, TransactionHash: str) -> dict:
        """
        根据交易哈希获取交易信息。包括交易哈希、所在区块号、交易索引号、交易状态、交易类型、交易行为、发送者、接收者、(部署的合约地址)、(GasPrice 或 (MaxFeePerGas 和 MaxPriorityFeePerGas))、GasLimit、GasUsed、Nonce、Value、Logs、InputData。

        参数：
            TransactionHash (str): 要查询的交易哈希

        返回值：
            TransactionInformation (dict): 交易信息构成的字典。当出现异常时返回 None 。
            {"TransactionHash"|"BlockNumber"|"TransactionIndex"|"Status"|"Type"|"Action"|"From"|"To"|("ContractAddress")|<"GasPrice"|("MaxFeePerGas"&"MaxPriorityFeePerGas")>|"GasLimit"|"GasUsed"|"Nonce"|"Value"|"Logs"|"InputData"}
        """
        try:
            Info = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=90)
            BlockNumber = Info.blockNumber
            TransactionIndex = Info.transactionIndex
            Status = Info.status
            From = Info["from"]
            To = Info.to
            ContractAddress = Info.contractAddress
            GasUsed = Info.gasUsed
            Logs = Info.logs
            Info = self.Net.eth.get_transaction(TransactionHash)
            TransactionHash = Info.hash.hex()
            GasPrice = Info.gasPrice
            MaxFeePerGas = Info.get("maxFeePerGas", None)
            MaxPriorityFeePerGas = Info.get("maxPriorityFeePerGas", None)
            GasLimit = Info.gas
            Nonce = Info.nonce
            Value = Info.value
            InputData = Info.input
            Type = "EIP-1559" if MaxFeePerGas else "Traditional"
            Action = "Deploy Contract" if To == None else "Call Contract" if self.Net.eth.get_code(Web3.toChecksumAddress(To)).hex() != "0x" else "Normal Transfer"
            ContractPrint = f"[ContractAddress]{ContractAddress}\n" if ContractAddress else ""
            GasPricePrint = f"[GasPrice]{Web3.fromWei(GasPrice, 'gwei')} Gwei" if Type == "Traditional" else f"[MaxFeePerGas]{Web3.fromWei(MaxFeePerGas, 'gwei')} Gwei\n[MaxPriorityFeePerGas]{Web3.fromWei(MaxPriorityFeePerGas, 'gwei')} Gwei"
            if Status:
                logger.success(
                    f"\n[Chain][GetTransactionInformationByHash]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[TransactionIndex]{TransactionIndex}\n[Status]Success\n[Type]{Type}\n[Action]{Action}\n[From]{From}\n[To]{To}\n{ContractPrint}{GasPricePrint}\n[GasLimit]{GasLimit} [GasUsed]{GasUsed}\n[Nonce]{Nonce} [Value]{Value}\n[Logs]{Logs}\n[InputData]{InputData}\n{'-'*80}")
            else:
                logger.error(
                    f"\n[Chain][GetTransactionInformationByHash]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[TransactionIndex]{TransactionIndex}\n[Status]Fail\n[Type]{Type}\n[Action]{Action}\n[From]{From}\n[To]{To}\n{ContractPrint}{GasPricePrint}\n[GasLimit]{GasLimit} [GasUsed]{GasUsed}\n[Nonce]{Nonce} [Value]{Value}\n[Logs]{Logs}\n[InputData]{InputData}\n{'-'*80}")
            return {"TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "TransactionIndex": TransactionIndex, "Status": Status, "Type": Type, "Action": Action, "From": From, "To": To, "ContractAddress": ContractAddress, "GasPrice": GasPrice, "GasLimit": GasLimit, "GasUsed": GasUsed, "Nonce": Nonce, "Value": Value, "Logs": Logs, "InputData": InputData} if Type == "Traditional" else {"TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "TransactionIndex": TransactionIndex, "Status": Status, "Type": Type, "Action": Action, "From": From, "To": To, "ContractAddress": ContractAddress, "MaxFeePerGas": MaxFeePerGas, "MaxPriorityFeePerGas": MaxPriorityFeePerGas, "GasLimit": GasLimit, "GasUsed": GasUsed, "Nonce": Nonce, "Value": Value, "Logs": Logs, "InputData": InputData}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Chain][GetTransactionInformationByHash]Failed to get transaction information\n[TransactionHash]{TransactionHash}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def GetTransactionInformationByBlockIdAndIndex(self, BlockID, TransactionIndex: int) -> dict:
        """
        根据区块 ID 和交易在块中的索引来获取交易信息。包括交易哈希、所在区块号、交易索引号、交易状态、交易类型、交易行为、发送者、接收者、(部署的合约地址)、(GasPrice 或 (MaxFeePerGas 和 MaxPriorityFeePerGas))、GasLimit、GasUsed、Nonce、Value、Logs、InputData。

        参数：
            BlockID (str|int): 区块 ID 。可为区块号或 'latest', 'earliest', 'pending' 。
            TransactionIndex (int): 交易在块中的索引

        返回值：
            TransactionInformation (dict): 交易信息构成的字典。当出现异常时返回 None 。
            {"TransactionHash"|"BlockNumber"|"TransactionIndex"|"Status"|"Type"|"Action"|"From"|"To"|("ContractAddress")|<"GasPrice"|("MaxFeePerGas"&"MaxPriorityFeePerGas")>|"GasLimit"|"GasUsed"|"Nonce"|"Value"|"Logs"|"InputData"}
        """
        try:
            Info = self.Net.eth.get_transaction_by_block(BlockID, TransactionIndex)
            TransactionHash = Info.hash.hex()
            BlockNumber = Info.blockNumber
            TransactionIndex = Info.transactionIndex
            From = Info["from"]
            To = Info.to
            GasPrice = Info.gasPrice
            MaxFeePerGas = Info.get("maxFeePerGas", None)
            MaxPriorityFeePerGas = Info.get("maxPriorityFeePerGas", None)
            GasLimit = Info.gas
            Nonce = Info.nonce
            Value = Info.value
            InputData = Info.input
            Info = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=90)
            Status = Info.status
            GasUsed = Info.gasUsed
            ContractAddress = Info.contractAddress
            Logs = Info.logs
            Type = "EIP-1559" if MaxFeePerGas else "Traditional"
            Action = "Deploy Contract" if To == None else "Call Contract" if self.Net.eth.get_code(Web3.toChecksumAddress(To)).hex() != "0x" else "Normal Transfer"
            ContractPrint = f"[ContractAddress]{ContractAddress}\n" if ContractAddress else ""
            GasPricePrint = f"[GasPrice]{Web3.fromWei(GasPrice, 'gwei')} Gwei" if Type == "Traditional" else f"[MaxFeePerGas]{Web3.fromWei(MaxFeePerGas, 'gwei')} Gwei\n[MaxPriorityFeePerGas]{Web3.fromWei(MaxPriorityFeePerGas, 'gwei')} Gwei"
            if Status:
                logger.success(
                    f"\n[Chain][GetTransactionInformationByBlockIdAndIndex]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[TransactionIndex]{TransactionIndex}\n[Status]Success\n[Type]{Type}\n[Action]{Action}\n[From]{From}\n[To]{To}\n{ContractPrint}{GasPricePrint}\n[GasLimit]{GasLimit} [GasUsed]{GasUsed}\n[Nonce]{Nonce} [Value]{Value}\n[Logs]{Logs}\n[InputData]{InputData}\n{'-'*80}")
            else:
                logger.error(
                    f"\n[Chain][GetTransactionInformationByBlockIdAndIndex]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[TransactionIndex]{TransactionIndex}\n[Status]Fail\n[Type]{Type}\n[Action]{Action}\n[From]{From}\n[To]{To}\n{ContractPrint}{GasPricePrint}\n[GasLimit]{GasLimit} [GasUsed]{GasUsed}\n[Nonce]{Nonce} [Value]{Value}\n[Logs]{Logs}\n[InputData]{InputData}\n{'-'*80}")
            return {"TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "TransactionIndex": TransactionIndex, "Status": Status, "Type": Type, "Action": Action, "From": From, "To": To, "ContractAddress": ContractAddress, "GasPrice": GasPrice, "GasLimit": GasLimit, "GasUsed": GasUsed, "Nonce": Nonce, "Value": Value, "Logs": Logs, "InputData": InputData} if Type == "Traditional" else {"TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "TransactionIndex": TransactionIndex, "Status": Status, "Type": Type, "Action": Action, "From": From, "To": To, "ContractAddress": ContractAddress, "MaxFeePerGas": MaxFeePerGas, "MaxPriorityFeePerGas": MaxPriorityFeePerGas, "GasLimit": GasLimit, "GasUsed": GasUsed, "Nonce": Nonce, "Value": Value, "Logs": Logs, "InputData": InputData}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Chain][GetTransactionInformationByBlockIdAndIndex]Failed to get transaction information\n[BlockID]{BlockID}\n[TransactionIndex]{TransactionIndex}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def GetBalance(self, Address: str) -> int:
        """
        根据账户地址获取其网络原生代币余额。

        参数：
            Address (str): 账户地址

        返回值：
            Balance (int): 账户网络原生代币余额。单位为 wei ，当出现异常时返回 None 。
        """
        try:
            Address = Web3.toChecksumAddress(Address)
            Balance = self.Net.eth.get_balance(Address)
            logger.success(f"\n[Chain][GetBalance]\n[Address]{Address}\n[Balance][{Balance} Wei]<=>[{Web3.fromWei(Balance,'ether')} Ether]\n{'-'*80}")
            return Balance
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Chain][GetBalance]Failed to get balance\n[Address]{Address}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def GetCode(self, Address: str) -> str:
        """
        根据合约地址获取其已部署字节码。

        参数：
            Address (str): 合约地址

        返回值：
            Code (str): 合约已部署字节码。含 0x 前缀的十六进制形式，当出现异常时返回 None 。
        """
        try:
            Address = Web3.toChecksumAddress(Address)
            Code = self.Net.eth.get_code(Address).hex()
            logger.success(f"\n[Chain][GetCode]\n[Address]{Address}\n[Code]{Code}\n{'-'*80}")
            return Code
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Chain][GetCode]Failed to get code\n[Address]{Address}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def GetStorage(self, Address: str, SlotIndex: int) -> str:
        """
        根据合约地址和存储插槽索引获取存储值。

        参数：
            Address (str): 合约地址
            SlotIndex (int): 存储插槽索引

        返回值：
            Data (str): 存储值。含 0x 前缀的十六进制形式，当出现异常时返回 None 。
        """
        try:
            Address = Web3.toChecksumAddress(Address)
            Data = self.Net.eth.get_storage_at(Address, SlotIndex).hex()
            logger.success(f"\n[Chain][GetStorage]\n[Address]{Address}\n[SlotIndex]{SlotIndex}\n[Value][Hex][{Data}]<=>[Dec][{int(Data,16)}]\n{'-'*80}")
            return Data
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Chain][GetStorage]Failed to get storage\n[Address]{Address}\n[SlotIndex]{SlotIndex}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def DumpStorage(self, Address: str, Count: int) -> list:
        """
        根据合约地址和指定插槽数量值，从插槽 0 开始批量遍历存储插槽并获取值。

        参数：
            Address (str): 合约地址
            Count (int): 指定插槽数量值

        返回值：
            Data (List[str]): 存储值列表。含 0x 前缀的十六进制形式，当出现异常时返回 None 。
        """
        try:
            Address = Web3.toChecksumAddress(Address)
            Data = [self.Net.eth.get_storage_at(Address, i).hex() for i in range(Count)]
            Temp = '\n'.join([f"[Slot {i}]{Data[i]}" for i in range(len(Data))])
            logger.success(f"\n[Chain][DumpStorage]\n[Address]{Address}\n{Temp}\n{'-'*80}")
            return Data
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Chain][DumpStorage]Failed to dump storage\n[Address]{Address}\n[slot 0 ... {Count-1}]\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def GetPublicKeyByTransactionHash(self, TransactionHash: str) -> tuple:
        """
        通过一笔已在链上确认的交易哈希，获取账户公钥。

        参数：
            TransactionHash (str): 交易哈希

        返回值：
            (Address, PublicKey) (tuple): 由账户地址和账户公钥组成的元组。当出现异常时返回 None 。
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
                f"\n[Chain][GetPublicKeyByTransactionHash]\n[TransactionHash]{TransactionHash}\n[Address]{Address}\n[PublicKey]{PublicKey}\n{'-'*80}")
            return (Address, PublicKey)
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Chain][GetPublicKeyByTransactionHash]\nFailed to get public key by transaction hash\n[TransactionHash]{TransactionHash}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None


class Account():
    """
    Account 是账户实例，作为发起链上调用的基础。
    """

    def __init__(self, Chain: Chain, PrivateKey: str):
        """
        初始化。通过私钥导入账户并与 Chain 实例绑定，后续的所有链上调用都会作用在 Chain 实例化表示的链上。当导入账户失败时将会抛出异常。

        参数：
            Chain (Poseidon.Blockchain.Chain): 区块链实例
            PrivateKey (str): 账户私钥。不含 0x 前缀的十六进制形式。

        成员变量：
            Chain (Poseidon.Blockchain.Chain): 区块链实例
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
            logger.success(f"\n[Account][Initialize]Successfully import account [{self.Address}]\n{'-'*80}")
            self.GetSelfBalance()
        except:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Account][Initialize]Failed to import account\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            raise Exception("Failed to import account.")

    def GetSelfBalance(self) -> int:
        """
        获取自身账户的网络原生代币余额。当余额为 0 时会触发无法发送交易的警告。

        返回值：
            Balance (int): 自身账户网络原生代币余额。单位为 wei ，当出现异常时返回 None 。
        """
        Balance = self.Chain.GetBalance(self.Address)
        if Balance == 0:
            logger.warning(f"\n[Account][GetSelfBalance]\n[Warning]This account's balance is insufficient to send transactions\n{'-'*80}")
        return Balance

    def Transfer(self, To: str, Value: int, GasLimit: int = 100000, Data: str = "0x") -> dict:
        """
        向指定账户转账指定数量的网络原生代币，可附带信息。若 90 秒内交易未确认则作超时处理。

        参数：
            To (str): 接收方地址
            Value (int): 发送的网络原生代币数量。单位为 wei 。
            GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 100000 wei 。
            Data (可选)(str): 交易数据。含 0x 前缀的十六进制形式，默认值为 "0x" 。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """
        try:
            From = Web3.toChecksumAddress(self.Address)
            To = Web3.toChecksumAddress(To)
            Txn = {
                "chainId": self.Chain.ChainId,
                "from": From,
                "to": To,
                "value": Value,
                "gas": GasLimit,
                "gasPrice": self.Net.eth.gas_price,
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "data": Data,
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            Txn["gasPrice"] = f'{Web3.fromWei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][Transfer]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}\n{'-'*80}")
            TransactionInformation = self.Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Account][Transfer]Failed to transfer\n[From]{From}\n[To]{To}\n[Value]{Value}[GasLimit]{GasLimit}\n[Data]{Data}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def SendTransaction(self, To: str, Data: str, Value: int = 0, GasLimit: int = 1000000) -> dict:
        """
        以传统方式发送一笔自定义交易。若 90 秒内交易未确认则作超时处理。

        参数：
            To (str): 接收方地址
            Data (str): 交易数据。含 0x 前缀的十六进制形式。
            Value (可选)(int): 随交易发送的网络原生代币数量。单位为 wei ，默认为 0 wei 。
            GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 1000000 wei 。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """
        try:
            From = Web3.toChecksumAddress(self.Address)
            To = Web3.toChecksumAddress(To)
            Txn = {
                "chainId": self.Chain.ChainId,
                "from": From,
                "to": To,
                "value": Value,
                "gas": GasLimit,
                "gasPrice": self.Net.eth.gas_price,
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "data": Data,
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            Txn["gasPrice"] = f'{Web3.fromWei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][SendTransaction][Traditional]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}\n{'-'*80}")
            TransactionInformation = self.Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Account][SendTransaction][Traditional]Failed to send transaction\n[From]{From}\n[To]{To}\n[Value]{Value}[GasLimit]{GasLimit}\n[Data]{Data}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def SendTransactionByEIP1559(self, To: str, Data: str, Value: int = 0, GasLimit: int = 1000000) -> dict:
        """
        以 EIP-1559 方式发送一笔自定义交易。若 90 秒内交易未确认则作超时处理。

        参数：
            To (str): 接收方地址
            Data (str): 交易数据。含 0x 前缀的十六进制形式。
            Value (可选)(int): 随交易发送的网络原生代币数量。单位为 wei ，默认为 0 wei 。
            GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 1000000 wei 。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """
        try:
            From = Web3.toChecksumAddress(self.Address)
            To = Web3.toChecksumAddress(To)
            BaseFee = self.Net.eth.gas_price
            MaxPriorityFee = self.Net.eth.max_priority_fee + Web3.toWei(1, "gwei")
            Txn = {
                "chainId": self.Chain.ChainId,
                "from": From,
                "to": To,
                "value": Value,
                "gas": GasLimit,
                "maxFeePerGas": BaseFee + MaxPriorityFee,
                "maxPriorityFeePerGas": MaxPriorityFee,
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "data": Data
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            Txn["maxFeePerGas"] = f'{Web3.fromWei(Txn["maxFeePerGas"],"gwei")} Gwei'
            Txn["maxPriorityFeePerGas"] = f'{Web3.fromWei(Txn["maxPriorityFeePerGas"],"gwei")} Gwei'
            logger.info(f"\n[Account][SendTransaction][EIP-1559]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}\n{'-'*80}")
            TransactionInformation = self.Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Account][SendTransaction][EIP-1559]Failed to send transaction\n[From]{From}\n[To]{To}\n[Value]{Value}[GasLimit]{GasLimit}\n[Data]{Data}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def DeployContract(self, ABI: dict, Bytecode: str, Value: int = 0, *Arguments) -> dict:
        """
        部署合约。若 90 秒内交易未确认则作超时处理。

        参数：
            ABI (dict): 合约 ABI
            Bytecode (str): 合约部署字节码。含 0x 前缀的十六进制形式。
            Value (可选)(int): 随交易发送给合约的网络原生代币数量。单位为 wei ，默认为 0 wei 。
            *Arguments (可选)(any): 传给合约构造函数的参数，默认为空。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
            当合约部署成功时，字典中会额外添加"Contract"字段，该变量是已实例化的 Contract 对象，失败时为 None。
        """
        try:
            DeployingContract = self.Net.eth.contract(abi=ABI, bytecode=Bytecode)
            TransactionData = DeployingContract.constructor(*Arguments).buildTransaction({"gasPrice": self.Net.eth.gas_price, "value": Value})
            Txn = {
                "chainId": self.Chain.ChainId,
                "from": Web3.toChecksumAddress(self.Address),
                "value": TransactionData["value"],
                "gas": TransactionData["gas"],
                "gasPrice": TransactionData["gasPrice"],
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "data": TransactionData["data"]
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            Txn["gasPrice"] = f'{Web3.fromWei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][DeployContract]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}\n{'-'*80}")
            TransactionInformation = self.Chain.GetTransactionInformationByHash(TransactionHash)
            if TransactionInformation["Status"]:
                DeployedContract = Contract(self, TransactionInformation["ContractAddress"], ABI)
                TransactionInformation["Contract"] = DeployedContract
                return TransactionInformation
            else:
                TransactionInformation["Contract"] = None
                return TransactionInformation
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Account][DeployContract]Failed to deploy contract\n[Value]{Value}\n[ABI]{ABI}\n[Bytecode]{Bytecode}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def DeployContractWithoutABI(self, Bytecode: str, Value: int = 0, GasLimit: int = 10000000) -> dict:
        """
        在没有 ABI 的情况下，仅使用字节码来部署合约。若 90 秒内交易未确认则作超时处理。

        参数：
            Bytecode (str): 合约部署字节码。含 0x 前缀的十六进制形式。
            Value (可选)(int): 随交易发送给合约的网络原生代币数量。单位为 wei ，默认为 0 wei 。
            GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 10000000 wei 。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """
        try:
            Txn = {
                "chainId": self.Chain.ChainId,
                "from": Web3.toChecksumAddress(self.Address),
                "value": Value,
                "gas": GasLimit,
                "gasPrice": self.Net.eth.gas_price,
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "data": Bytecode,
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            Txn["gasPrice"] = f'{Web3.fromWei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][DeployContractWithoutABI]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}\n{'-'*80}")
            TransactionInformation = self.Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Account][DeployContractWithoutABI]Failed to deploy contract\n[Value]{Value}\n[GasLimit]{GasLimit}\n[Bytecode]{Bytecode}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def SignMessage(self, Message: str) -> dict:
        """
        消息字符串进行签名。

        参数：
            Message (str): 待签名消息字符串

        返回值：
            SignatureData (str): 签名数据构成的字典。当出现异常时返回 None 。
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
                f"\n[Account][SignMessage]\n[Address]{self.Address}\n[Message]{Message}\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[R]{R}\n[S]{S}\n[V]{V}\n{'-'*80}")
            return {"Address": self.Address, "Message": Message, "MessageHash": MessageHash, "Signature": Signature, "R": R, "S": S, "V": V}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Account][SignMessage]Failed to sign message\n[Address]{self.Address}\n[Message]{Message}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def SignMessageHash(self, MessageHash: str) -> dict:
        """
        对消息哈希进行签名。

        参数：
            MessageHash (str): 待签名消息哈希

        返回值：
            SignatureData (str): 签名数据构成的字典。当出现异常时返回 None 。
            {"Address"|"MessageHash"|"Signature"|"R"|"S"|"V"}
        """
        try:
            SignedMessage = EthAccount.signHash(MessageHash, self.PrivateKey)
            Signature = SignedMessage.signature.hex()
            R = hex(SignedMessage.r)
            S = hex(SignedMessage.s)
            V = hex(SignedMessage.v)
            logger.success(
                f"\n[Account][SignMessageHash]\n[Address]{self.Address}\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[R]{R}\n[S]{S}\n[V]{V}\n{'-'*80}")
            return {"Address": self.Address, "MessageHash": MessageHash, "Signature": Signature, "R": R, "S": S, "V": V}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Account][SignMessageHash]Failed to sign message hash\n[Address]{self.Address}\n[MessageHash]{MessageHash}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None


class Contract():
    """
    Contract 是合约实例，作为与指定合约进行交互的基础。
    """

    def __init__(self, Account: Account, Address: str, ABI: dict):
        """
        初始化。通过合约地址与 ABI 来实例化合约，并与 Account 绑定，后续所有对该合约的调用都会由这一账户发起。当实例化失败时会抛出异常。

        参数：
            Account (Poseidon.Blockchain.Account): 账户实例
            Address (str): 合约地址
            ABI (str): 合约 ABI

        成员变量：
            Account (Poseidon.Blockchain.Account): 账户实例
            Address (str): 合约地址
            Instance (Web3.eth.Contract): web3.py 原生 contract 对象实例
        """
        try:
            self.Account = Account
            self.Net = Account.Net
            self.Address = Web3.toChecksumAddress(Address)
            self.Instance = self.Net.eth.contract(address=self.Address, abi=ABI)
            logger.success(f"\n[Contract][Initialize]Successfully instantiated contract [{self.Address}]\n{'-'*80}")
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[Contract][Initialize]Failed to instantiated contract [{self.Address}]\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            raise Exception("Failed to instantiate contract.")

    def CallFunction(self, FunctionName: str, *FunctionArguments) -> dict:
        """
        通过传入函数名及参数来调用该合约内的函数。

        参数：
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(any): 函数参数，默认为空。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """
        TransactionData = self.Instance.functions[FunctionName](*FunctionArguments).buildTransaction({"gasPrice": self.Net.eth.gas_price})
        logger.info(f"\n[Contract][CallFunction]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n{'-'*80}")
        TransactionInformation = self.Account.SendTransaction(self.Address, TransactionData["data"], TransactionData["value"], TransactionData["gas"])
        return TransactionInformation

    def CallFunctionWithValueAndGasLimit(self, Value: int, GasLimit: int, FunctionName: str, *FunctionArguments) -> dict:
        """
        通过传入函数名及参数来调用该合约内的函数。支持自定义 Value 和 GasLimit 。

        参数：
            Value (int): 随交易发送的网络原生代币数量。单位为 wei 。
            GasLimit (int): Gas 最大使用量。单位为 wei 。
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(any): 函数参数，默认为空。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """
        TransactionData = self.Instance.functions[FunctionName](*FunctionArguments).buildTransaction({"gasPrice": self.Net.eth.gas_price, "gas": GasLimit, "value": Value})
        logger.info(
            f"\n[Contract][CallFunctionWithValueAndGasLimit]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[Value]{TransactionData['value']} [GasLimit]{TransactionData['gas']}\n{'-'*80}")
        TransactionInformation = self.Account.SendTransaction(self.Address, TransactionData["data"], TransactionData["value"], TransactionData["gas"])
        return TransactionInformation

    def ReadOnlyCallFunction(self, FunctionName: str, *FunctionArguments):
        """
        通过传入函数名及参数来调用该合约内的只读函数。

        参数：
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(any): 函数参数，默认为空。

        返回值：
            Result (any): 调用函数后得到的返回值。当出现异常时返回 None 。
        """
        try:
            Result = self.Instance.functions[FunctionName](*FunctionArguments).call()
            logger.success(f"\n[Contract][ReadOnlyCallFunction]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[Result]{Result}\n{'-'*80}")
            return Result
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Contract][ReadOnlyCallFunction]Failed to call readonly function\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    def EncodeABI(self, FunctionName: str, *FunctionArguments) -> str:
        """
        通过传入函数名及参数进行编码，相当于生成调用该函数的 CallData 。

        参数：
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(any): 函数参数，默认为空。

        返回值：
            CallData (str): 调用数据编码。含 0x 前缀的十六进制形式。当出现异常时返回 None 。
        """
        try:
            CallData = self.Instance.encodeABI(fn_name=FunctionName, args=FunctionArguments)
            logger.success(f"\n[Contract][EncodeABI]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[CallData]{CallData}\n{'-'*80}")
            return CallData
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[Contract][EncodeABI]Failed to encode abi\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None


class BlockchainUtils():
    """
    通用工具集，整合了链下使用的常用功能。
    """

    @staticmethod
    def SwitchSolidityVersion(SolidityVersion: str):
        """
        设置当前使用的 Solidity 版本，若该版本未安装则会自动安装。当设置版本失败时会抛出异常。

        参数：
            SolidityVersion (str): Solidity 版本号
        """
        from solcx import install_solc, set_solc_version
        try:
            install_solc(SolidityVersion)
            set_solc_version(SolidityVersion)
            logger.success(f"\n[BlockchainUtils][SwitchSolidityVersion]Current Solidity Version [{SolidityVersion}]\n{'-'*80}")
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[BlockchainUtils][SwitchSolidityVersion]Failed to switch to version [{SolidityVersion}]\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            raise Exception("Failed to switch solidity version.")

    @staticmethod
    def Compile(FileCourse: str, ContractName: str, SolidityVersion: str = None, AllowPaths: str = None, Optimize: bool = False) -> tuple:
        """
        根据给定的参数使用 py-solc-x 编译合约。当编译失败时会抛出异常。

        参数：
            FileCourse (str): 合约文件完整路径。当合约文件与脚本文件在同一目录下时可直接使用文件名。
            ContractName (str): 要编译的合约名称
            SolidityVersion (可选)(str): 指定使用的 Solidity 版本。若不指定则会使用当前已激活的 Solidity 版本进行编译。默认为 None 。
            AllowPaths (可选)(str): 指定许可路径。在编译时可能会出现 AllowPaths 相关错误可在这里解决。默认为 None 。
            Optimize (可选)(str): 是否开启优化器。默认为 False 。

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
            logger.success(f"\n[BlockchainUtils][Compile]\n[FileCourse]{FileCourse}\n[ContractName]{ContractName}\n[ABI]{ABI}\n[Bytecode]{Bytecode}\n{'-'*80}")
            return (ABI, Bytecode)
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][Compile]Failed to compile the contract\n[FileCourse]{FileCourse}\n[ContractName]{ContractName}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            raise Exception("Failed to compile the contract.")

    @staticmethod
    def CreateNewAccount() -> tuple:
        """
        创建新账户。

        返回值：
            (Address, PrivateKey) (tuple): 由账户地址和私钥组成的元组
        """
        Temp = EthAccount.create()
        Address = Web3.toChecksumAddress(Temp.address)
        PrivateKey = Temp.privateKey.hex()
        logger.success(f"\n[BlockchainUtils][CreateNewAccount]\n[Address]{Address}\n[PrivateKey]{PrivateKey}\n{'-'*80}")
        return (Address, PrivateKey)

    @staticmethod
    def MnemonicToAddressAndPrivateKey(Mnemonic: str) -> tuple:
        """
        将助记词转换为账户地址与私钥。参考 BIP-39 标准。

        参数：
            Mnemonic (str): 助记词字符串。以空格进行分隔。

        返回值：
            (Address, PrivateKey) (tuple): 由账户地址和私钥组成的元组。当出现异常时返回 None 。
        """
        try:
            EthAccount.enable_unaudited_hdwallet_features()
            Temp = EthAccount.from_mnemonic(Mnemonic)
            Address = Web3.toChecksumAddress(Temp.address)
            PrivateKey = Temp.privateKey.hex()
            logger.success(f"\n[BlockchainUtils][MnemonicToAddressAndPrivateKey]\n[Mnemonic]{Mnemonic}\n[Address]{Address}\n[PrivateKey]{PrivateKey}\n{'-'*80}")
            return (Address, PrivateKey)
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][MnemonicToAddressAndPrivateKey]Failed to convert mnemonic to address and private key\n[Mnemonic]{Mnemonic}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    @staticmethod
    def RecoverMessage(Message: str, Signature: str) -> str:
        """
        通过消息原文和签名还原出签署者的账户地址。

        参数：
            Message (str): 消息原文
            Signature (str): 签名

        返回值：
            Signer (str): 签署者的账户地址。当出现异常时返回 None 。
        """
        from eth_account.messages import encode_defunct
        try:
            Temp = encode_defunct(text=Message)
            Signer = EthAccount.recover_message(Temp, signature=Signature)
            logger.success(f"\n[BlockchainUtils][RecoverMessage]\n[Message]{Message}\n[Signature]{Signature}\n[Signer]{Signer}\n{'-'*80}")
            return Signer
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][RecoverMessage]Failed to recover message\n[Message]{Message}\n[Signature]{Signature}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    @staticmethod
    def RecoverMessageHash(MessageHash: str, Signature: str) -> str:
        """
        通过消息哈希和签名还原出签署者的账户地址。

        参数：
            MessageHash (str): 消息哈希
            Signature (str): 签名

        返回值：
            Signer (str): 签署者的账户地址。当出现异常时返回 None 。
        """
        try:
            Signer = EthAccount.recoverHash(MessageHash, signature=Signature)
            logger.success(f"\n[BlockchainUtils][RecoverMessageByHash]\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[Signer]{Signer}\n{'-'*80}")
            return Signer
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][RecoverMessageByHash]Failed to recover message hash\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    @staticmethod
    def RecoverRawTransaction(RawTransactionData: str) -> str:
        """
        获取签署此交易的账户地址。

        参数：
            RawTransactionData (str): 原生交易数据。含 0x 前缀的十六进制形式。

        返回值：
            Address (str): 账户地址。当出现异常时返回 None 。
        """
        try:
            Address = EthAccount.recover_transaction(RawTransactionData)
            logger.success(f"\n[BlockchainUtils][RecoverRawTransaction]\n[RawTransactionData]{RawTransactionData}\n[Address]{Address}\n{'-'*80}")
            return Address
        except:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][RecoverRawTransaction]Failed to recover raw transaction\n[RawTransactionData]{RawTransactionData}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    @staticmethod
    def CrackSelector(SourceFunctionName: str, SourceFunctionParameters: list, ToGenerateFunctionParameters: list) -> str:
        """
        根据源函数名、参数与想要碰撞生成的函数的参数，碰撞生成出一个函数名，以使得这两个函数的选择器签名相等。

        参数：
            SourceFunctionName (str): 目标函数名
            SourceFunctionParameters (List[str]): 目标函数参数列表
            ToGenerateFunctionParameters (List[str]): 想要碰撞生成的函数的参数列表

        返回值：
            ToGenerateFunction (str): 碰撞出的函数的名称与参数完整表示。当出现异常时返回 None 。
        """
        from pwn import pwnlib
        from pwnlib.util.iters import mbruteforce

        def Crack(SourceFunctionSelector: str, Temp: str) -> str:
            Charset = "0123456789abcdef"
            X = mbruteforce(lambda x: Web3.keccak(f"function_{x}({Temp})".encode())[:4].hex() == SourceFunctionSelector, Charset, 8, method='fixed')
            return f"function_{x}({Temp})"
        try:
            SourceFunctionSelector = Web3.keccak(f"{SourceFunctionName}({','.join(SourceFunctionParameters)})".encode())[:4].hex()
            Temp = ','.join(ToGenerateFunctionParameters)
            logger.info(
                f"\n[BlockchainUtils][CrackSelector]\n[SourceFunction]{SourceFunctionName}({','.join(SourceFunctionParameters)})\n[SourceFunctionSelector]{SourceFunctionSelector}\n[ToGenerateFunction]function_?({Temp})\nCrack start...")
            ToGenerateFunction = Crack(SourceFunctionSelector, Temp)
            ToGenerateFunctionSelector = Web3.keccak(ToGenerateFunction.encode())[:4].hex()
            logger.success(f"\n[BlockchainUtils][CrackSelector]\n[ToGenerateFunction]{ToGenerateFunction}\n[ToGenerateSelector]{ToGenerateSelector}\n{'-'*80}")
            return ToGenerateFunction
        except:
            ExceptionInformation = exc_info()
            Temp = ','.join(ToGenerateFunctionParameters)
            logger.error(
                f"\n[BlockchainUtils][CrackSelector]Failed to crack selector\n[SourceFunction]{SourceFunctionName}({','.join(SourceFunctionParameters)})\n[ToGenerateFunction]{f'function_?({Temp})'}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    @staticmethod
    def AssemblyToBytecode(Assembly: str) -> str:
        """
        将 EVM Assembly 转为 EVM Bytecode 。

        参数：
            Assembly (str): EVM Assembly

        返回值：
            Bytecode (str): EVM Bytecode 。含 0x 前缀的六进制形式。当出现异常时返回 None 。
        """
        try:
            from pyevmasm import assemble_hex
            Bytecode = assemble_hex(Assembly)
            logger.success(f"\n[BlockchainUtils][AssemblyToBytecode]\n[Bytecode]{Bytecode}\n{'-'*80}")
            return Bytecode
        except:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][AssemblyToBytecod]Failed to transform assembly to bytecode\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    @staticmethod
    def BytecodeToAssembly(Bytecode: str) -> str:
        """
        将 EVM Bytecode 转为 EVM Assembly 。

        参数：
            Bytecode (str): EVM Bytecode 。含 0x 前缀的十六进制形式。

        返回值：
            Assembly (str): EVM Assembly 。当出现异常时返回 None 。
        """
        try:
            from pyevmasm import disassemble_hex
            Assembly = disassemble_hex(Bytecode)
            logger.success(f"\n[BlockchainUtils][AssemblyToBytecode]\n[Assembly]\n{Assembly}\n{'-'*80}")
            return Assembly
        except:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][BytecodeToAssembly]Failed to transform bytecode to assembly\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    @staticmethod
    def SignatureToRSV(Signature: str) -> dict:
        """
        将签名解析成 R S V 。

        参数：
            Signature (str): 签名。含 0x 前缀的十六进制形式。

        返回值：
            Result (dict): 解析结果。当出现异常时返回 None 。
            {"Signature"|"R"|"S"|"V"}
        """
        try:
            Signature = hex(int(Signature, 16))
            assert (len(Signature) == 132)
            R = '0x' + Signature[2:66]
            S = '0x' + Signature[66:-2]
            V = '0x' + Signature[-2:]
            logger.success(f"\n[BlockchainUtils][SignatureToRSV]\n[Signature]{Signature}\n[R]{R}\n[S]{S}\n[V]{V}\n{'-'*80}")
            Result = {"Signature": Signature, "R": R, "S": S, "V": V}
            return Result
        except:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][SignatureToRSV]Failed to transform signature to rsv\n[Signature]{Signature}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None

    @staticmethod
    def RSVToSignature(R: str, S: str, V: str) -> dict:
        """
        将 R S V 合并成签名。

        参数：
            R (str): 签名 r 值。含 0x 前缀的十六进制形式。
            S (str): 签名 s 值。含 0x 前缀的十六进制形式。
            V (str): 签名 v 值。含 0x 前缀的十六进制形式。

        返回值：
            Result (dict): 合并结果。当出现异常时返回 None 。
            {"R"|"S"|"V"|"Signature"}
        """
        try:
            R = hex(int(R, 16))
            S = hex(int(S, 16))
            V = hex(int(V, 16))
            assert (len(R) == 64 + 2 and len(S) == 64 + 2 and len(V) == 2 + 2)
            Signature = '0x' + R[2:] + S[2:] + V[2:]
            logger.success(f"\n[BlockchainUtils][RSVToSignature]\n[R]{R}\n[S]{S}\n[V]{V}\n[Signature]{Signature}\n{'-'*80}")
            Result = {"R": R, "S": S, "V": V, "Signature": Signature}
            return Result
        except:
            ExceptionInformation = exc_info()
            logger.error(
                f"\n[BlockchainUtils][RSVToSignature]Failed to transform rsv to signature\n[R]{R}\n[S]{S}\n[V]{V}\n[ExceptionInformation]{ExceptionInformation}\n{'-'*80}")
            return None
