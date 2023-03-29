"""
本模块可用于与任何以太坊同构链（即通常所说的 EVM 链）进行交互，支持常用的链上交互操作。
"""

from web3 import Web3
from eth_account import Account as EthAccount
from loguru import logger
from typing import Optional, Union, List, Any
from traceback import format_exc
from json import dump, dumps
import os

LogPath = os.path.join("logs", "Poseidon_{time}.log")
logger.add(LogPath)


class Chain():
    """
    Chain 是区块链实例，后续的所有链上交互的操作都将经由该指定节点处理。
    """

    def __init__(self, RPCUrl: str, RequestParams: Optional[dict] = None):
        """
        初始化。根据给定的节点 RPC 地址进行连接，可通过代理访问。当连接节点失败时会抛出异常。

        参数：
            RPCUrl (str): 节点 RPC 地址
            RequestParams (可选)(Optional[dict]): 连接时使用的 request 参数，默认为 None。
            例如当需要使用代理进行访问时，则传入 RequestParams={"proxies": {"http": "http://localhost:<ProxyPort>","https": "http://localhost:<ProxyPort>"}}

        成员变量：
            ChainId (int): 链 ID
            Node (Web3.HTTPProvider): web3.py 原生的 HTTP 交互器实例
            Eth (Web3.HTTPProvider.eth): HTTP 交互器实例中的 eth 模块
        """

        from time import time
        from web3 import HTTPProvider
        from web3.middleware import geth_poa_middleware
        RequestParamsPrint = f"[RequestParams]{RequestParams}\n" if RequestParams else ""
        StartTime = time()
        self.Node = Web3(HTTPProvider(RPCUrl, request_kwargs=RequestParams))
        if self.Node.is_connected():
            FinishTime = time()
            Delay = round((FinishTime - StartTime) * 1000)
            logger.success(f"\n[Chain][Initialize]Connected to [{RPCUrl}] [{Delay} ms]\n{RequestParamsPrint}{'-'*80}")
            self.Node.middleware_onion.inject(geth_poa_middleware, layer=0)
            self.Eth = self.Node.eth
            self.GetBasicInformation()
        else:
            logger.error(f"\n[Chain][Initialize]Failed to connect to [{RPCUrl}]\n{RequestParamsPrint}{'-'*80}")
            raise Exception("Failed to connect to chain.")

    def GetBasicInformation(self) -> dict:
        """
        获取区块链基本信息。包括链 ID 、区块高度、 GasPrice 、出块间隔、当前节点的客户端软件版本号。

        返回值：
            BasicInformation (dict): 区块链基本信息构成的字典。
            {"ChainId"|"BlockNumber"|"GasPrice"|"Timeslot"|"ClientVersion"}
        """

        self.ChainId, BlockNumber, GasPrice, ClientVersion = self.Eth.chain_id, self.Eth.block_number, self.Eth.gas_price, self.Node.client_version
        Timeslot = self.Eth.get_block(BlockNumber).timestamp - self.Eth.get_block(BlockNumber - 1).timestamp
        logger.success(
            f"\n[Chain][GetBasicInformation]\n[ChainId]{self.ChainId}\n[BlockNumber]{BlockNumber}\n[GasPrice]{Web3.from_wei(GasPrice, 'gwei')} Gwei\n[Timeslot]{Timeslot}s\n[ClientVersion]{ClientVersion}\n{'-'*80}"
        )
        return {"ChainId": self.ChainId, "BlockNumber": BlockNumber, "GasPrice": GasPrice, "Timeslot": Timeslot, "ClientVersion": ClientVersion}

    def GetTransactionInformationByHash(self, TransactionHash: str) -> dict:
        """
        根据交易哈希查询该交易的详细回执信息。包括交易哈希、所在区块号、交易索引号、交易状态、交易类型、交易行为、发送者、接收者、(部署的合约地址)、(GasPrice 或 (MaxFeePerGas 和 MaxPriorityFeePerGas))、GasLimit、GasUsed、Nonce、Value、R、S、V、Logs、InputData。

        参数：
            TransactionHash (str): 要查询的交易的哈希

        返回值：
            TransactionInformation (dict): 交易信息构成的字典。当出现异常时返回 None 。
            {"TransactionHash"|"BlockNumber"|"TransactionIndex"|"Status"|"Type"|"Action"|"From"|"To"|("ContractAddress")|<"GasPrice"|("MaxFeePerGas"&"MaxPriorityFeePerGas")>|"GasLimit"|"GasUsed"|"Nonce"|"Value"|"R"|"S"|"V"|"Logs"|"InputData"}
        """

        try:
            Info = self.Eth.wait_for_transaction_receipt(TransactionHash, timeout=120)
            BlockNumber, TransactionIndex, Status, From, To, ContractAddress, GasUsed, Logs = Info.blockNumber, Info.transactionIndex, Info.status, Info["from"], Info.to, Info.contractAddress, Info.gasUsed, Web3.to_json(Info.logs)
            Info = self.Eth.get_transaction(TransactionHash)
            TransactionHash, GasPrice, MaxFeePerGas, MaxPriorityFeePerGas, GasLimit, Nonce, Value, R, S, V, InputData = Info.hash.hex(), Info.gasPrice, Info.get("maxFeePerGas", None), Info.get("maxPriorityFeePerGas", None), Info.gas, Info.nonce, Info.value, Info.r.hex(), Info.s.hex(), Info.v, Info.input
            Type = "EIP-1559" if MaxFeePerGas or MaxPriorityFeePerGas else "Traditional"
            Action = "Deploy Contract" if To == None else "Call Contract" if self.Eth.get_code(Web3.to_checksum_address(To)).hex() != "0x" else "Normal Transfer"
            ContractPrint = f"[ContractAddress]{ContractAddress}\n" if ContractAddress else ""
            GasPricePrint = f"[GasPrice]{Web3.from_wei(GasPrice, 'gwei')} Gwei" if Type == "Traditional" else f"[MaxFeePerGas]{Web3.from_wei(MaxFeePerGas, 'gwei')} Gwei\n[MaxPriorityFeePerGas]{Web3.from_wei(MaxPriorityFeePerGas, 'gwei')} Gwei"
            GeneralPrint = f"\n[Chain][GetTransactionInformationByHash]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[TransactionIndex]{TransactionIndex}\n[Status]{'Success' if Status else 'Fail'}\n[Type]{Type}\n[Action]{Action}\n[From]{From}\n[To]{To}\n{ContractPrint}{GasPricePrint}\n[GasLimit]{GasLimit} [GasUsed]{GasUsed}\n[Nonce]{Nonce} [Value]{Value}\n[R]{R}\n[S]{S}\n[V]{V}\n[Logs]{Logs}\n[InputData]{InputData}\n{'-'*80}"
            if Status:
                logger.success(GeneralPrint)
            else:
                logger.error(GeneralPrint)
            return {"TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "TransactionIndex": TransactionIndex, "Status": Status, "Type": Type, "Action": Action, "From": From, "To": To, "ContractAddress": ContractAddress, "GasPrice": GasPrice, "MaxFeePerGas": MaxFeePerGas, "MaxPriorityFeePerGas": MaxPriorityFeePerGas, "GasLimit": GasLimit, "GasUsed": GasUsed, "Nonce": Nonce, "Value": Value, "R": R, "S": S, "V": V, "Logs": Logs, "InputData": InputData}
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Chain][GetTransactionInformationByHash]Failed\n[TransactionHash]{TransactionHash}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None

    def GetTransactionInformationByBlockIdAndIndex(self, BlockID: Union[str, int], TransactionIndex: int) -> dict:
        """
        根据区块 ID 和交易在块中的索引来查询该交易的详细回执信息。包括交易哈希、所在区块号、交易索引号、交易状态、交易类型、交易行为、发送者、接收者、(部署的合约地址)、(GasPrice 或 (MaxFeePerGas 和 MaxPriorityFeePerGas))、GasLimit、GasUsed、Nonce、Value、R、S、V、Logs、InputData。

        参数：
            BlockID (Union[str,int]): 区块 ID 。可为区块号数值或 'latest', 'earliest', 'pending' 。
            TransactionIndex (int): 交易在块中的索引

        返回值：
            TransactionInformation (dict): 交易信息构成的字典。当出现异常时返回 None 。
            {"TransactionHash"|"BlockNumber"|"TransactionIndex"|"Status"|"Type"|"Action"|"From"|"To"|("ContractAddress")|<"GasPrice"|("MaxFeePerGas"&"MaxPriorityFeePerGas")>|"GasLimit"|"GasUsed"|"Nonce"|"Value"|"R"|"S"|"V"|"Logs"|"InputData"}
        """

        try:
            Info = self.Eth.get_transaction_by_block(BlockID, TransactionIndex)
            TransactionHash, BlockNumber, TransactionIndex, From, To, GasPrice, MaxFeePerGas, MaxPriorityFeePerGas, GasLimit, Nonce, Value, R, S, V, InputData = Info.hash.hex(), Info.blockNumber, Info.transactionIndex, Info["from"], Info.to, Info.gasPrice, Info.get("maxFeePerGas", None), Info.get("maxPriorityFeePerGas", None), Info.gas, Info.nonce, Info.value, Info.r.hex(), Info.s.hex(), Info.v, Info.input
            Info = self.Eth.wait_for_transaction_receipt(TransactionHash, timeout=120)
            Status, GasUsed, ContractAddress, Logs = Info.status, Info.gasUsed, Info.contractAddress, Info.logs
            Type = "EIP-1559" if MaxFeePerGas else "Traditional"
            Action = "Deploy Contract" if To == None else "Call Contract" if self.Eth.get_code(Web3.toChecksumAddress(To)).hex() != "0x" else "Normal Transfer"
            ContractPrint = f"[ContractAddress]{ContractAddress}\n" if ContractAddress else ""
            GasPricePrint = f"[GasPrice]{Web3.from_wei(GasPrice, 'gwei')} Gwei" if Type == "Traditional" else f"[MaxFeePerGas]{Web3.from_wei(MaxFeePerGas, 'gwei')} Gwei\n[MaxPriorityFeePerGas]{Web3.from_wei(MaxPriorityFeePerGas, 'gwei')} Gwei"
            GeneralPrint = f"\n[Chain][GetTransactionInformationByBlockIdAndIndex]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[TransactionIndex]{TransactionIndex}\n[Status]{'Success' if Status else 'Fail'}\n[Type]{Type}\n[Action]{Action}\n[From]{From}\n[To]{To}\n{ContractPrint}{GasPricePrint}\n[GasLimit]{GasLimit} [GasUsed]{GasUsed}\n[Nonce]{Nonce} [Value]{Value}\n[R]{R}\n[S]{S}\n[V]{V}\n[Logs]{Logs}\n[InputData]{InputData}\n{'-'*80}"
            if Status:
                logger.success(GeneralPrint)
            else:
                logger.error(GeneralPrint)
            return {"TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "TransactionIndex": TransactionIndex, "Status": Status, "Type": Type, "Action": Action, "From": From, "To": To, "ContractAddress": ContractAddress, "GasPrice": GasPrice, "MaxFeePerGas": MaxFeePerGas, "MaxPriorityFeePerGas": MaxPriorityFeePerGas, "GasLimit": GasLimit, "GasUsed": GasUsed, "Nonce": Nonce, "Value": Value, "R": R, "S": S, "V": V, "Logs": Logs, "InputData": InputData}
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Chain][GetTransactionInformationByBlockIdAndIndex]Failed\n[BlockID]{BlockID}\n[TransactionIndex]{TransactionIndex}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None

    def GetBlockInformation(self, BlockID: Union[str, int]) -> dict:
        """
        根据区块 ID 获取该区块的详细信息。包括区块号、区块哈希、矿工、时间戳、GasLimit、GasUsed、块内交易的哈希集合。

        参数：
            BlockID (Union[str,int]): 区块 ID 。可为区块号数值或 'latest', 'earliest', 'pending' 。

        返回值：
            BlockInformation (dict): 区块信息构成的字典。当出现异常时返回 None 。
            {"BlockNumber"|"BlockHash"|"Miner"|"TimeStamp"|"GasLimit"|"GasUsed"|"Transactions"}
        """

        try:
            Info = self.Eth.get_block(BlockID)
            BlockNumber, BlockHash, Miner, TimeStamp, GasLimit, GasUsed, Transactions = Info.number, Info.hash.hex(), Info.miner, Info.timestamp, Info.gasLimit, Info.gasUsed, Web3.to_json(Info.transactions)
            logger.success(
                f"\n[Chain][GetBlockInformation]\n[BlockNumber]{BlockNumber}\n[BlockHash]{BlockHash}\n[Miner]{Miner}\n[TimeStamp]{TimeStamp}\n[GasLimit]{GasLimit}\n[GasUsed]{GasUsed}\n[Transactions]{Transactions}"
            )
            return {"BlockNumber": BlockNumber, "BlockHash": BlockHash, "Miner": Miner, "TimeStamp": TimeStamp, "GasLimit": GasLimit, "GasUsed": GasUsed, "Transactions": Transactions}
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Chain][GetBlockInformation]Failed\n[BlockID]{BlockID}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
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
            Address = Web3.to_checksum_address(Address)
            Balance = self.Eth.get_balance(Address)
            logger.success(
                f"\n[Chain][GetBalance]\n[Address]{Address}\n[Balance][{Balance} Wei]<=>[{Web3.from_wei(Balance,'ether')} Ether]\n{'-'*80}"
            )
            return Balance
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(f"\n[Chain][GetBalance]Failed\n[Address]{Address}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}")
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
            Address = Web3.to_checksum_address(Address)
            Code = self.Eth.get_code(Address).hex()
            logger.success(f"\n[Chain][GetCode]\n[Address]{Address}\n[Code]{Code}\n{'-'*80}")
            return Code
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(f"\n[Chain][GetCode]Failed\n[Address]{Address}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}")
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
            Address = Web3.to_checksum_address(Address)
            Data = self.Eth.get_storage_at(Address, SlotIndex).hex()
            logger.success(
                f"\n[Chain][GetStorage]\n[Address]{Address}\n[SlotIndex]{SlotIndex}\n[Value][Hex][{Data}]<=>[Dec][{int(Data,16)}]\n{'-'*80}"
            )
            return Data
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Chain][GetStorage]Failed\n[Address]{Address}\n[SlotIndex]{SlotIndex}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
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
            Address = Web3.to_checksum_address(Address)
            Data = [self.Eth.get_storage_at(Address, i).hex() for i in range(Count)]
            Temp = '\n'.join([f"[Slot {i}]{Data[i]}" for i in range(len(Data))])
            logger.success(f"\n[Chain][DumpStorage]\n[Address]{Address}\n{Temp}\n{'-'*80}")
            return Data
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Chain][DumpStorage]Failed\n[Address]{Address}\n[slot 0 ... {Count-1}]\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
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
            Transaction = self.Eth.get_transaction(TransactionHash)
            Signature = self.Eth.account._keys.Signature(vrs=(to_standard_v(extract_chain_id(Transaction.v)[1]), Web3.to_int(Transaction.r), Web3.to_int(Transaction.s)))
            UnsignedTransactionDict = {i: Transaction[i] for i in ['chainId', 'nonce', 'gasPrice' if int(
                Transaction.type, 0) != 2 else '', 'gas', 'to', 'value', 'accessList', 'maxFeePerGas', 'maxPriorityFeePerGas'] if i in Transaction}
            UnsignedTransactionDict['data'] = Transaction['input']
            UnsignedTransaction = serializable_unsigned_transaction_from_dict(UnsignedTransactionDict)
            Temp = Signature.recover_public_key_from_msg_hash(UnsignedTransaction.hash())
            PublicKey = str(Temp).replace('0x', '0x04')  # 比特币未压缩公钥格式
            Address = Temp.to_checksum_address()
            logger.success(
                f"\n[Chain][GetPublicKeyByTransactionHash]\n[TransactionHash]{TransactionHash}\n[Address]{Address}\n[PublicKey]{PublicKey}\n{'-'*80}"
            )
            return (Address, PublicKey)
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Chain][GetPublicKeyByTransactionHash]Failed\n[TransactionHash]{TransactionHash}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None


class Account():
    """
    Account 是账户实例，后续的交易将经由该指定账户发送至链上。
    """

    def __init__(self, Chain: Chain, PrivateKey: str):
        """
        初始化。通过私钥导入账户并与 Chain 实例绑定，后续的交易将经由该指定账户发送至链上。当导入账户失败时将会抛出异常。

        参数：
            Chain (Poseidon.Blockchain.Chain): 区块链实例
            PrivateKey (str): 账户私钥。不含 0x 前缀的十六进制形式。

        成员变量：
            EthAccount (eth_account.Account): eth_account 的原生 Account 对象实例
        """

        try:
            self.EthAccount, self._Chain, self._Eth = EthAccount.from_key(PrivateKey), Chain, Chain.Eth
            self._Eth.default_account = self.EthAccount.address
            logger.success(f"\n[Account][Initialize]Successfully import account [{self.EthAccount.address}]\n{'-'*80}")
            self.RequestAuthorizationBeforeSendTransaction(False)
            self.GetSelfBalance()
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(f"\n[Account][Initialize]Failed to import account\n[ExceptionInformation]{ExceptionInformation}{'-'*80}")
            raise Exception("Failed to import account.")

    def RequestAuthorizationBeforeSendTransaction(self, Open: bool = True):
        """
        设置在通过该账户发送每一笔交易之前是否请求授权。开启后会在每笔交易即将发送前暂停流程，在终端询问是否发送该笔交易。在实例化 Account 对象时默认设置为 False 。

        参数：
            Open (bool): 请求授权开关。函数定义的默认值为 True ，但在实例化 Account 对象时默认设置为 False 。
        """

        self._Request = Open
        if self._Request:
            logger.success(f"\n[Account][RequestAuthorizationBeforeSendTransaction]Status: True\n{'-'*80}")
        else:
            logger.warning(f"\n[Account][RequestAuthorizationBeforeSendTransaction]Status: False\n{'-'*80}")

    def GetSelfBalance(self) -> int:
        """
        获取自身账户的网络原生代币余额。

        返回值：
            Balance (int): 自身账户网络原生代币余额。单位为 wei ，当出现异常时返回 None 。
        """

        Balance = self._Chain.GetBalance(self.EthAccount.address)
        if Balance == 0:
            logger.warning(f"\n[Account][GetSelfBalance]\n[Warning]This account's balance is insufficient to send transactions\n{'-'*80}")
        return Balance

    def Transfer(self, To: str, Value: int, Data: str = "0x", GasPrice: Optional[int] = None, GasLimit: int = 100000) -> dict:
        """
        向指定账户转账指定数量的网络原生代币，可附带信息。若 120 秒内交易未确认则作超时处理。

        参数：
            To (str): 接收方地址
            Value (int): 发送的网络原生代币数量。单位为 wei 。
            Data (可选)(str): 交易数据。含 0x 前缀的十六进制形式，默认值为 "0x" 。
            GasPrice (可选)(Optional[int]): Gas 价格。单位为 wei ，默认使用 RPC 建议的 gas_price 。
            GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 100000 wei 。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """

        try:
            From = self.EthAccount.address
            To = Web3.to_checksum_address(To)
            Txn = {
                "chainId": self._Chain.ChainId,
                "from": From,
                "to": To,
                "value": Value,
                "gas": GasLimit,
                "gasPrice": GasPrice if GasPrice else self._Eth.gas_price,
                "nonce": self._Eth.get_transaction_count(From),
                "data": Data,
            }
            SignedTxn = self.EthAccount.sign_transaction(Txn)
            Txn["gasPrice"] = f'{Web3.from_wei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][Transfer]\n[Txn]{dumps(Txn, indent=2)}\n{'-'*80}")
            if self._Request:
                logger.warning(f"\n[Account][RequestAuthorizationBeforeSendTransaction][True]\nDo you confirm sending this transaction?")
                Command = input("Command Input (yes/1/[Enter] or no/0):")
                if Command == "no" or Command == "0" or (len(Command) > 0 and Command != "yes" and Command != "1"):
                    raise Exception("Cancel sending transaction.")
            print("pending...")
            TransactionHash = self._Eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            TransactionInformation = self._Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][Transfer]Failed\n[From]{From}\n[To]{To}\n[Value]{Value}\n[GasPrice]{GasPrice}\n[GasLimit]{GasLimit}\n[Data]{Data}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None

    def SendTransaction(self, To: str, Data: str, Value: int = 0, GasPrice: Optional[int] = None, GasLimit: int = 1000000) -> dict:
        """
        以传统方式发送一笔自定义交易。若 120 秒内交易未确认则作超时处理。

        参数：
            To (str): 接收方地址
            Data (str): 交易数据。含 0x 前缀的十六进制形式。
            Value (可选)(int): 随交易发送的网络原生代币数量。单位为 wei ，默认为 0 wei 。
            GasPrice (可选)(Optional[int]): Gas 价格。单位为 wei ，默认使用 RPC 建议的 gas_price 。
            GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 1000000 wei 。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """

        try:
            From = self.EthAccount.address
            To = Web3.to_checksum_address(To)
            Txn = {
                "chainId": self._Chain.ChainId,
                "from": From,
                "to": To,
                "value": Value,
                "gas": GasLimit,
                "gasPrice": GasPrice if GasPrice else self._Eth.gas_price,
                "nonce": self._Eth.get_transaction_count(From),
                "data": Data,
            }
            SignedTxn = self.EthAccount.sign_transaction(Txn)
            Txn["gasPrice"] = f'{Web3.from_wei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][SendTransaction][Traditional]\n[Txn]{dumps(Txn, indent=2)}\n{'-'*80}")
            if self._Request:
                logger.warning(f"\n[Account][RequestAuthorizationBeforeSendTransaction][True]\nDo you confirm sending this transaction?")
                Command = input("Command Input (yes/1/[Enter] or no/0):")
                if Command == "no" or Command == "0" or (len(Command) > 0 and Command != "yes" and Command != "1"):
                    raise Exception("Cancel sending transaction.")
            print("pending...")
            TransactionHash = self._Eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            TransactionInformation = self._Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][SendTransaction][Traditional]Failed\n[From]{From}\n[To]{To}\n[Value]{Value}\n[GasPrice]{GasPrice}\n[GasLimit]{GasLimit}\n[Data]{Data}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None

    def SendTransactionByEIP1559(self, To: str, Data: str, Value: int = 0, BaseFee: Optional[int] = None, MaxPriorityFee: Optional[int] = None, GasLimit: int = 1000000) -> dict:
        """
        以 EIP-1559 方式发送一笔自定义交易。若 120 秒内交易未确认则作超时处理。

        参数：
            To (str): 接收方地址
            Data (str): 交易数据。含 0x 前缀的十六进制形式。
            Value (可选)(int): 随交易发送的网络原生代币数量。单位为 wei ，默认为 0 wei 。
            BaseFee (可选)(Optional[int]): BaseFee 价格。单位为 wei ，默认使用 RPC 建议的 gas_price 。
            MaxPriorityFee (可选)(Optional[int]): MaxPriorityFee 价格。单位为 wei ，默认使用 RPC 建议的 max_priority_fee 。
            GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 1000000 wei 。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """

        try:
            From = self.EthAccount.address
            To = Web3.to_checksum_address(To)
            BaseFee = BaseFee if BaseFee else self._Eth.gas_price
            MaxPriorityFee = MaxPriorityFee if MaxPriorityFee else self._Eth.max_priority_fee
            Txn = {
                "chainId": self._Chain.ChainId,
                "from": From,
                "to": To,
                "value": Value,
                "gas": GasLimit,
                "maxFeePerGas": BaseFee + MaxPriorityFee,
                "maxPriorityFeePerGas": MaxPriorityFee,
                "nonce": self._Eth.get_transaction_count(From),
                "data": Data
            }
            SignedTxn = self.EthAccount.sign_transaction(Txn)
            Txn["maxFeePerGas"] = f'{Web3.from_wei(Txn["maxFeePerGas"],"gwei")} Gwei'
            Txn["maxPriorityFeePerGas"] = f'{Web3.from_wei(Txn["maxPriorityFeePerGas"],"gwei")} Gwei'
            logger.info(f"\n[Account][SendTransaction][EIP-1559]\n[Txn]{dumps(Txn, indent=2)}\n{'-'*80}")
            if self._Request:
                logger.warning(f"\n[Account][RequestAuthorizationBeforeSendTransaction][True]\nDo you confirm sending this transaction?")
                Command = input("Command Input (yes/1/[Enter] or no/0):")
                if Command == "no" or Command == "0" or (len(Command) > 0 and Command != "yes" and Command != "1"):
                    raise Exception("Cancel sending transaction.")
            print("pending...")
            TransactionHash = self._Eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            TransactionInformation = self._Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][SendTransaction][EIP-1559]Failed\n[From]{From}\n[To]{To}\n[Value]{Value}\n[BaseFee]{BaseFee}\n[MaxPriorityFee]{MaxPriorityFee}\n[GasLimit]{GasLimit}\n[Data]{Data}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None

    def DeployContract(self, ABI: dict, Bytecode: str, Value: int = 0, GasPrice: Optional[int] = None, *Arguments: Optional[Any]) -> dict:
        """
        部署合约。若 120 秒内交易未确认则作超时处理。

        参数：
            ABI (dict): 合约 ABI
            Bytecode (str): 合约部署字节码。含 0x 前缀的十六进制形式。
            Value (可选)(int): 随交易发送给合约的网络原生代币数量。单位为 wei ，默认为 0 wei 。
            GasPrice (可选)(Optional[int]): Gas 价格。单位为 wei ，默认使用 RPC 建议的 gas_price 。
            *Arguments (可选)(Optional[Any]): 传给合约构造函数的参数，默认为空。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
            当合约部署成功时，字典中会额外添加"Contract"字段，该变量是已实例化的 Contract 对象，失败时为 None。
        """

        try:
            DeployingContract = self._Eth.contract(abi=ABI, bytecode=Bytecode)
            TransactionData = DeployingContract.constructor(*Arguments).buildTransaction({"value": Value, "gasPrice": GasPrice if GasPrice else self._Eth.gas_price})
            Txn = {
                "chainId": self._Chain.ChainId,
                "from": self.EthAccount.address,
                "value": TransactionData["value"],
                "gas": TransactionData["gas"],
                "gasPrice": TransactionData["gasPrice"],
                "nonce": self._Eth.get_transaction_count(self.EthAccount.address),
                "data": TransactionData["data"]
            }
            SignedTxn = self.EthAccount.sign_transaction(Txn)
            Txn["gasPrice"] = f'{Web3.from_wei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][DeployContract]\n[Txn]{dumps(Txn, indent=2)}\n{'-'*80}")
            if self._Request:
                logger.warning(f"\n[Account][RequestAuthorizationBeforeSendTransaction][True]\nDo you confirm sending this transaction?")
                Command = input("Command Input (yes/1/[Enter] or no/0):")
                if Command == "no" or Command == "0" or (len(Command) > 0 and Command != "yes" and Command != "1"):
                    raise Exception("Cancel sending transaction.")
            print("pending...")
            TransactionHash = self._Eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            TransactionInformation = self._Chain.GetTransactionInformationByHash(TransactionHash)
            if TransactionInformation["Status"]:
                DeployedContract = Contract(self, TransactionInformation["ContractAddress"], ABI)
                TransactionInformation["Contract"] = DeployedContract
                return TransactionInformation
            else:
                TransactionInformation["Contract"] = None
                return TransactionInformation
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][DeployContract]Failed\n[Value]{Value}\n[GasPrice]{GasPrice}\n[ABI]{ABI}\n[Bytecode]{Bytecode}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None

    def DeployContractWithoutABI(self, Bytecode: str, Value: int = 0, GasPrice: Optional[int] = None, GasLimit: int = 5000000) -> dict:
        """
        在没有 ABI 的情况下，仅使用字节码来部署合约。若 120 秒内交易未确认则作超时处理。

        参数：
            Bytecode (str): 合约部署字节码。含 0x 前缀的十六进制形式。
            Value (可选)(int): 随交易发送给合约的网络原生代币数量。单位为 wei ，默认为 0 wei 。
            GasPrice (可选)(Optional[int]): Gas 价格。单位为 wei ，默认使用 RPC 建议的 gas_price 。
            GasLimit (可选)(int): Gas 最大使用量。单位为 wei ，默认为 5000000 wei 。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """

        try:
            Txn = {
                "chainId": self._Chain.ChainId,
                "from": self.EthAccount.address,
                "value": Value,
                "gas": GasLimit,
                "gasPrice": self._Eth.gas_price,
                "nonce": GasPrice if GasPrice else self._Eth.get_transaction_count(self.EthAccount.address),
                "data": Bytecode,
            }
            SignedTxn = self.EthAccount.sign_transaction(Txn)
            Txn["gasPrice"] = f'{Web3.from_wei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][DeployContractWithoutABI]\n[Txn]{dumps(Txn, indent=2)}\n{'-'*80}")
            if self._Request:
                logger.warning(f"\n[Account][RequestAuthorizationBeforeSendTransaction][True]\nDo you confirm sending this transaction?")
                Command = input("Command Input (yes/1/[Enter] or no/0):")
                if Command == "no" or Command == "0" or (len(Command) > 0 and Command != "yes" and Command != "1"):
                    raise Exception("Cancel sending transaction.")
            print("pending...")
            TransactionHash = self._Eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            TransactionInformation = self._Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][DeployContractWithoutABI]Failed\n[Value]{Value}\n[GasPrice]{GasPrice}\n[GasLimit]{GasLimit}\n[Bytecode]{Bytecode}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
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

        try:
            from eth_account.messages import encode_defunct
            SignedMessage = self.EthAccount.sign_message(encode_defunct(text=Message))
            MessageHash, Signature, R, S, V = SignedMessage.messageHash.hex(), SignedMessage.signature.hex(), hex(SignedMessage.r), hex(SignedMessage.s), SignedMessage.v
            logger.success(
                f"\n[Account][SignMessage]\n[Address]{self.EthAccount.address}\n[Message]{Message}\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[R]{R}\n[S]{S}\n[V]{V}\n{'-'*80}"
            )
            return {"Address": self.EthAccount.address, "Message": Message, "MessageHash": MessageHash, "Signature": Signature, "R": R, "S": S, "V": V}
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][SignMessage]Failed to sign message\n[Address]{self.EthAccount.address}\n[Message]{Message}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
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
            SignedMessage = self.EthAccount.signHash(MessageHash)
            Signature, R, S, V = SignedMessage.signature.hex(), hex(SignedMessage.r), hex(SignedMessage.s), SignedMessage.v
            logger.success(
                f"\n[Account][SignMessageHash]\n[Address]{self.EthAccount.address}\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[R]{R}\n[S]{S}\n[V]{V}\n{'-'*80}"
            )
            return {"Address": self.EthAccount.address, "MessageHash": MessageHash, "Signature": Signature, "R": R, "S": S, "V": V}
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][SignMessageHash]Failed\n[Address]{self.EthAccount.address}\n[MessageHash]{MessageHash}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None


class Contract():
    """
    Contract 是合约实例，作为与指定合约进行交互的基础。
    """

    def __init__(self, Account: Account, Address: str, ABI: dict):
        """
        初始化。通过合约地址与 ABI 来实例化合约，并与 Account 绑定，后续所有对该合约的调用都会由这一账户发起。当合约实例化失败时会抛出异常。

        参数：
            Account (Poseidon.Blockchain.Account): 账户实例
            Address (str): 合约地址
            ABI (str): 合约 ABI

        成员变量：
            Instance (Web3.eth.Contract): web3.py 原生 contract 对象实例
            Address (str): 合约地址
        """

        try:
            self._Account, self._Eth, self.Address = Account, Account._Eth, Web3.to_checksum_address(Address)
            self.Instance = self._Eth.contract(address=self.Address, abi=ABI)
            logger.success(f"\n[Contract][Initialize]Successfully instantiated contract [{self.Address}]\n{'-'*80}")
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Contract][Initialize]Failed to instantiated contract [{self.Address}]\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            raise Exception("Failed to instantiate contract.")

    def CallFunction(self, FunctionName: str, *FunctionArguments: Optional[Any]) -> dict:
        """
        通过传入函数名及参数来调用该合约内的函数。

        参数：
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(Optional[Any]): 函数参数，默认为空。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """

        TransactionData = self.Instance.functions[FunctionName](*FunctionArguments).buildTransaction({"gasPrice": self._Eth.gas_price})
        logger.info(f"\n[Contract][CallFunction]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n{'-'*80}")
        TransactionInformation = self._Account.SendTransaction(self.Address, TransactionData["data"], TransactionData["value"], TransactionData['gasPrice'], TransactionData["gas"])
        return TransactionInformation

    def CallFunctionWithParameters(self, Value: int, GasPrice: Optional[int], GasLimit: int, FunctionName: str, *FunctionArguments: Optional[Any]) -> dict:
        """
        通过传入函数名及参数来调用该合约内的函数。支持自定义 Value 和 GasLimit 。

        参数：
            Value (int): 随交易发送的网络原生代币数量。单位为 wei 。
            GasPrice (Optional[int]): Gas 价格。单位为 wei ，默认使用 RPC 建议的 gas_price 。
            GasLimit (int): Gas 最大使用量。单位为 wei 。
            FunctionName (str): 函数名称
            *FunctionArguments (Optional[Any]): 函数参数，默认为空。

        返回值：
            TransactionInformation (dict): 交易信息构成的字典，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """

        TransactionData = self.Instance.functions[FunctionName](*FunctionArguments).buildTransaction({"value": Value, "gasPrice": GasPrice if GasPrice else self._Eth.gas_price, "gas": GasLimit})
        logger.info(
            f"\n[Contract][CallFunctionWithValueAndGasLimit]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[Value]{TransactionData['value']}\n[GasPrice]{TransactionData['gasPrice']}\n[GasLimit]{TransactionData['gas']}\n{'-'*80}"
        )
        TransactionInformation = self._Account.SendTransaction(self.Address, TransactionData["data"], TransactionData["value"], TransactionData['gasPrice'], TransactionData["gas"])
        return TransactionInformation

    def ReadOnlyCallFunction(self, FunctionName: str, *FunctionArguments: Optional[Any]) -> Any:
        """
        通过传入函数名及参数来调用该合约内的只读函数。

        参数：
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(Optional[Any]): 函数参数，默认为空。

        返回值：
            Result (Any): 调用函数后得到的返回值。当出现异常时返回 None 。
        """

        try:
            Result = self.Instance.functions[FunctionName](*FunctionArguments).call()
            logger.success(
                f"\n[Contract][ReadOnlyCallFunction]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[Result]{Result}\n{'-'*80}"
            )
            return Result
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Contract][ReadOnlyCallFunction]Failed\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None

    def EncodeABI(self, FunctionName: str, *FunctionArguments: Optional[Any]) -> str:
        """
        通过传入函数名及参数进行编码，相当于生成调用该函数的 CallData 。

        参数：
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(Optional[Any]): 函数参数，默认为空。

        返回值：
            CallData (str): 调用数据编码。含 0x 前缀的十六进制形式。当出现异常时返回 None 。
        """

        try:
            CallData = self.Instance.encodeABI(fn_name=FunctionName, args=FunctionArguments)
            logger.success(
                f"\n[Contract][EncodeABI]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[CallData]{CallData}\n{'-'*80}"
            )
            return CallData
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Contract][EncodeABI]Failed\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None


class BlockchainUtils():
    """
    通用工具集，整合了常用的链下操作。静态类，无需实例化。
    """

    @staticmethod
    def SwitchSolidityVersion(SolidityVersion: str):
        """
        设置当前使用的 Solidity 版本，若该版本未安装则会自动安装。

        参数：
            SolidityVersion (str): Solidity 版本号
        """

        try:
            from solcx import install_solc, set_solc_version
            install_solc(SolidityVersion)
            set_solc_version(SolidityVersion)
            logger.success(f"\n[BlockchainUtils][SwitchSolidityVersion]Current Solidity Version [{SolidityVersion}]\n{'-'*80}")
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][SwitchSolidityVersion]Failed to switch to version [{SolidityVersion}]\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )

    @staticmethod
    def Compile(FileCourse: str, ContractName: str, SolidityVersion: Optional[str] = None, AllowPaths: Optional[str] = None, Optimize: bool = False) -> tuple:
        """
        根据给定的参数使用 py-solc-x 编译合约。当编译失败时会抛出异常。

        参数：
            FileCourse (str): 合约文件完整路径。当合约文件与脚本文件在同一目录下时可直接使用文件名。
            ContractName (str): 要编译的合约名称
            SolidityVersion (可选)(Optional[str]): 指定使用的 Solidity 版本。若不指定则会使用当前已激活的 Solidity 版本进行编译。默认为 None 。
            AllowPaths (可选)(Optional[str]): 指定许可路径。在编译时可能会出现 AllowPaths 相关错误可在这里解决。默认为 None 。
            Optimize (可选)(bool): 是否开启优化器。默认为 False 。

        返回值：
            (ABI, Bytecode) (tuple): 由 ABI 和 Bytecode 组成的元组
        """

        try:
            from solcx import compile_source
            with open(FileCourse, "r", encoding="utf-8") as sol:
                CompiledSol = compile_source(sol.read(), solc_version=SolidityVersion, allow_paths=AllowPaths, optimize=Optimize, output_values=['abi', 'bin'])
            ContractData = CompiledSol[f'<stdin>:{ContractName}']
            ABI, Bytecode = ContractData['abi'], ContractData['bin']
            with open(f'{ContractName}_ABI.json', 'w', encoding="utf-8") as f:
                dump(ABI, f, indent=4)
            logger.success(
                f"\n[BlockchainUtils][Compile]\n[FileCourse]{FileCourse}\n[ContractName]{ContractName}\n[ABI]{ABI}\n[Bytecode]{Bytecode}\n{'-'*80}"
            )
            return (ABI, Bytecode)
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][Compile]Failed\n[FileCourse]{FileCourse}\n[ContractName]{ContractName}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            raise Exception("Failed to compile the contract.")

    @staticmethod
    def CreateNewAccount() -> tuple:
        """
        创建新账户。

        返回值：
            (Address, PrivateKey) (tuple): 由账户地址和私钥组成的元组
        """

        Temp = EthAccount.create()
        Address, PrivateKey = Web3.to_checksum_address(Temp.address), Temp.privateKey.hex()
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
            Address, PrivateKey = Web3.to_checksum_address(Temp.address), Temp.privateKey.hex()
            logger.success(
                f"\n[BlockchainUtils][MnemonicToAddressAndPrivateKey]\n[Mnemonic]{Mnemonic}\n[Address]{Address}\n[PrivateKey]{PrivateKey}\n{'-'*80}"
            )
            return (Address, PrivateKey)
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][MnemonicToAddressAndPrivateKey]Failed\n[Mnemonic]{Mnemonic}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None

    @staticmethod
    def GweiToWei(Value: Union[int, float]) -> int:
        """
        将一个正整数或浮点数按照 Gwei 为单位直接转化为 wei 为单位的正整数。即假设传入 Value = 1，将返回 1000000000 。

        参数：
            Value (Union[int,float]): 假设以 Gwei 为单位的待转换值。

        返回值：
            Result (int): 已转换为以 wei 为单位的值。当出现异常时返回 None 。
        """
        try:
            assert(Value > 0)
            return int(Value * 10**9)
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][GweiToWei]Failed\n[Value]{Value}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
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
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][AssemblyToBytecod]Failed\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
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
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][BytecodeToAssembly]Failed\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
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
            assert (len(Signature) == 130 + 2)
            R, S, V = '0x' + Signature[2:66], '0x' + Signature[66:-2], int('0x' + Signature[-2:], 16)
            logger.success(f"\n[BlockchainUtils][SignatureToRSV]\n[Signature]{Signature}\n[R]{R}\n[S]{S}\n[V]{V}\n{'-'*80}")
            return {"Signature": Signature, "R": R, "S": S, "V": V}
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][SignatureToRSV]Failed\n[Signature]{Signature}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None

    @staticmethod
    def RSVToSignature(R: str, S: str, V: str) -> dict:
        """
        将 R S V 合并成签名。

        参数：
            R (str): 签名 r 值。含 0x 前缀的十六进制形式。
            S (str): 签名 s 值。含 0x 前缀的十六进制形式。
            V (int): 签名 v 值。含 0x 前缀的十六进制形式。

        返回值：
            Result (dict): 合并结果。当出现异常时返回 None 。
            {"R"|"S"|"V"|"Signature"}
        """

        try:
            R, S, V = hex(int(R, 16)), hex(int(S, 16)), hex(int(V, 16))
            assert (len(R) == 64 + 2 and len(S) == 64 + 2 and len(V) == 2 + 2)
            Signature = '0x' + R[2:] + S[2:] + V[2:]
            logger.success(f"\n[BlockchainUtils][RSVToSignature]\n[R]{R}\n[S]{S}\n[V]{V}\n[Signature]{Signature}\n{'-'*80}")
            return {"R": R, "S": S, "V": V, "Signature": Signature}
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][RSVToSignature]Failed\n[R]{R}\n[S]{S}\n[V]{V}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None

    @staticmethod
    def GetFunctionSelector(FunctionName: str, FunctionParameters: Optional[List[str]] = None) -> str:
        """
        获取四字节函数选择器。

        参数：
            FunctionName (str): 函数名称。
            FunctionParameters (可选)(Optional[List[str]]): 函数参数列表。默认为空。

        返回值：
            Result (str): 四字节函数选择器。含 0x 前缀的十六进制形式
        """
        try:
            FunctionSelector = Web3.keccak(f"{FunctionName}({','.join(FunctionParameters)})".encode())[:4].hex()
            logger.success(f"\n[BlockchainUtils][GetFunctionSelector]\n[FunctionName]{FunctionName}\n[FunctionParameters]{FunctionParameters}\n[FunctionSelector]{FunctionSelector}\n{'-'*80}")
            return FunctionSelector
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][GetFunctionSelector]Failed\n[FunctionName]{FunctionName}\n[FunctionParameters]{FunctionParameters}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
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

        try:
            from eth_account.messages import encode_defunct
            Signer = EthAccount.recover_message(encode_defunct(text=Message), signature=Signature)
            logger.success(f"\n[BlockchainUtils][RecoverMessage]\n[Message]{Message}\n[Signature]{Signature}\n[Signer]{Signer}\n{'-'*80}")
            return Signer
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][RecoverMessage]Failed\n[Message]{Message}\n[Signature]{Signature}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
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
            logger.success(
                f"\n[BlockchainUtils][RecoverMessageByHash]\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[Signer]{Signer}\n{'-'*80}"
            )
            return Signer
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][RecoverMessageByHash]Failed\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
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
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][RecoverRawTransaction]Failed\n[RawTransactionData]{RawTransactionData}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None

    @staticmethod
    def CrackSelector(SourceFunctionName: str, SourceFunctionParameters: List[str], ToGenerateFunctionParameters: List[str]) -> str:
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
            return f"function_{X}({Temp})"

        try:
            Temp = ','.join(ToGenerateFunctionParameters)
            SourceFunctionSelector = Web3.keccak(f"{SourceFunctionName}({','.join(SourceFunctionParameters)})".encode())[:4].hex()
            logger.info(
                f"\n[BlockchainUtils][CrackSelector]\n[SourceFunction]{SourceFunctionName}({','.join(SourceFunctionParameters)})\n[SourceFunctionSelector]{SourceFunctionSelector}\n[ToGenerateFunction]function_?({Temp})\nCrack start..."
            )
            ToGenerateFunction = Crack(SourceFunctionSelector, Temp)
            ToGenerateFunctionSelector = Web3.keccak(ToGenerateFunction.encode())[:4].hex()
            logger.success(
                f"\n[BlockchainUtils][CrackSelector]\n[ToGenerateFunction]{ToGenerateFunction}\n[ToGenerateFunctionSelector]{ToGenerateFunctionSelector}\n{'-'*80}"
            )
            return ToGenerateFunction
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][CrackSelector]Failed\n[SourceFunction]{SourceFunctionName}({','.join(SourceFunctionParameters)})\n[ToGenerateFunction]{f'function_?({Temp})'}\n[ExceptionInformation]{ExceptionInformation}{'-'*80}"
            )
            return None
