from loguru import logger
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
from Crypto.Util.number import bytes_to_long
from solcx import compile_source
import json


class Chain():
    def __init__(self, RPCUrl: str) -> None:
        Net = Web3(HTTPProvider(RPCUrl))
        if Net.isConnected():
            self.Net = Net
            self.Net.middleware_onion.inject(geth_poa_middleware, layer=0)
            logger.success(f"\n[ConnectToChain]Successfully connected to [{RPCUrl}].")
            # self.ShowBasicInformation()
            # self.ShowBlockInformation()
        else:
            self.Net = None
            logger.error(f"\n[ConnectToChain]Failed to connect to [{RPCUrl}].")

    def ShowBasicInformation(self) -> None:
        ClientVersion = self.Net.clientVersion
        ChainId = self.Net.eth.chainId
        BlockNumber = self.Net.eth.block_number
        PeerCount = self.Net.net.peer_count
        logger.info(f"\n[BasicInformation]\n[ClientVersion]{ClientVersion}\n[ChainId]{ChainId}\n[BlockNumber]{BlockNumber}\n[PeerCount]{PeerCount}")

    def ShowBlockInformation(self, BlockID="latest") -> None:
        Data = self.Net.eth.get_block(BlockID)
        BlockNumber = Data["number"]
        TimeStamp = Data["timestamp"]
        CoinBase = Data["miner"]
        TransactionCount = len(Data["transactions"])
        # TransactionHashs = [hex(bytes_to_long(bytes(i))) for i in Data["transactions"]]
        # ExtraData = Data.get("extraData", "None")
        # ProofOfAuthorityData = Data.get("proofOfAuthorityData", "None")
        logger.info(f"\n[BlockInformation][{BlockID}]\n[BlockNumber]{BlockNumber}\n[TimeStamp]{TimeStamp}\n[CoinBase]{CoinBase}\n[TransactionCount]{TransactionCount}")

    def ShowTransactionByHash(self, TransactionHash: str) -> None:
        Data = self.Net.eth.get_transaction(TransactionHash)
        BlockNumber = Data["blockNumber"]
        TransactionIndex = Data["transactionIndex"]
        From = Data["from"]
        To = Data["to"]
        InputData = Data["input"]
        Value = Data["value"]
        logger.info(f"\n[TransactionInformation][{TransactionHash}]\n[BlockNumber]{BlockNumber}\n[TransactionIndex]{TransactionIndex}\n[From]{From}\n[To]{To}\n[InputData]{InputData}\n[Value]{Value}")

    def ShowTransactionByBlockIdAndIndex(self, BlockID, TransactionID: int) -> None:
        Data = self.Net.eth.get_transaction_by_block(BlockID, TransactionID)
        BlockNumber = Data["blockNumber"]
        TransactionIndex = Data["transactionIndex"]
        From = Data["from"]
        To = Data["to"]
        InputData = Data["input"]
        Value = Data["value"]
        logger.info(
            f"\n[TransactionInformation][{BlockID}][{TransactionID}]\n[BlockNumber]{BlockNumber}\n[TransactionIndex]{TransactionIndex}\n[From]{From}\n[To]{To}\n[InputData]{InputData}\n[Value]{Value}")

    def GetBalanceByAddress(self, Address: str) -> int:
        Balance = self.Net.eth.get_balance(Address)
        logger.info(f"\n[Balance][{Address}]\n[{Balance} Wei]<=>[{Web3.fromWei(Balance,'ether')} Ether]")
        return Balance

    def GetCodeByAddress(self, Address: str) -> str:
        Code = hex(bytes_to_long(self.Net.eth.get_code(Address)))
        logger.info(f"\n[Bytecode][{Address}]\n{Code}")
        return Code

    def GetStorage(self, Address: str, Index: int) -> str:
        Data = bytes_to_long(self.Net.eth.get_storage_at(Address, Index))
        DataHex = hex(Data)
        logger.info(f"\n[Storage][{Address}][{Index}]\n[Hex][{DataHex}]<=>[Dec][{Data}]")
        return Data

    def DumpStorage(self, Address: str, Count: int) -> list:
        Data = [hex(bytes_to_long(self.Net.eth.get_storage_at(Address, i))) for i in range(Count)]
        Temp = '\n'.join(Data)
        logger.info(f"\n[Storage][{Address}][slot 0 ... {Count-1}]\n{Temp}")
        return Data


class Account():
    def __init__(self, Chain: Chain, PrivateKey: str) -> None:
        try:
            self.Chain = Chain
            self.Net = Chain.Net
            AccountTemp = self.Net.eth.account.from_key(PrivateKey)
            self.Address = Web3.toChecksumAddress(AccountTemp.address)
            self.PrivateKey = AccountTemp.privateKey
            self.Net.eth.default_account = self.Address
            logger.success(f"\n[ImportAccount]Successfully import account. [Address]{self.Address}")
        except:
            logger.error(f"\n[ImportAccount]Failed to import through the private key of [{PrivateKey}].")

    def GetSelfBalance(self) -> int:
        Balance = self.Chain.GetBalanceByAddress(self.Address)
        return Balance

    def SendTransaction(self, To: str, Data: str, Value: int = 0, Gas: int = 3000000) -> dict:
        Txn = {
            "from": self.Address,
            "to": Web3.toChecksumAddress(To),
            "gasPrice": self.Net.eth.gas_price * 1.5,
            "gas": Gas,
            "nonce": self.Net.eth.get_transaction_count(self.Address),
            "value": Value,
            "data": Data,
            "chainId": self.Net.eth.chainId
        }
        SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
        TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
        logger.info(f"\n[SendTransaction]\n[TransactionHash]{TransactionHash}\n[Txn]{Txn}")
        TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=180)
        logger.success(f"\n[ConfirmTransaction]\n[TransactionHash]{TransactionHash}\n[TransactionReceipt]{TransactionReceipt}")
        return TransactionReceipt

    def DeployContract(self, ABI: dict, Bytecode: str, Value: int = 0) -> str:
        Contract = self.Net.eth.contract(abi=ABI, bytecode=Bytecode)
        # logger.info(f"\n[DeployContract]\n[ABI]{ABI}\n[Bytecode]{Bytecode}")
        TransactionData = Contract.constructor().buildTransaction({"value": Value})
        Txn = {
            "from": self.Address,
            "gasPrice": self.Net.eth.gas_price * 1.5,
            "gas": Contract.constructor().estimateGas(),
            "nonce": self.Net.eth.get_transaction_count(self.Address),
            "value": TransactionData["value"],
            "data": TransactionData["data"],
            "chainId": self.Net.eth.chainId
        }
        SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
        TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
        logger.info(f"\n[DeployContract]\n[TransactionHash]{TransactionHash}\n[Txn]{Txn}")
        TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=180)
        ContractAddress = TransactionReceipt.contractAddress
        Contract = Contract(Account, ContractAddress, ABI)
        logger.success(f"\n[ConfirmDeploy]\n[TransactionHash]{TransactionHash}\n[ContractAddress]{ContractAddress}")
        return (ContractAddress, Contract)

    @staticmethod
    def CreateNewAccount() -> tuple:
        Net = Web3()
        Keys = Net.eth.account.create()
        Address = Net.toChecksumAddress(Keys.address)
        PrivateKey = hex(bytes_to_long(Keys.privateKey))
        logger.success(f"\n[NewAccount]\n[Address]{Address}\n[PrivateKey]{PrivateKey}")
        return (Address, PrivateKey)


class Contract():
    def __init__(self, Account: Account, Address: str, ABI: dict) -> None:
        try:
            self.Account = Account
            self.Net = Account.Net
            self.Address = Web3.toChecksumAddress(Address)
            self.ABI = ABI
            self.Instance = self.Net.eth.contract(address=Address, abi=ABI)
            logger.success(f"\n[InstantiateContract][{self.Address}]Successfully instantiated contract. ")
        except:
            logger.error(f"\n[InstantiateContract][{self.Address}]Failed to instantiated contract.")

    def CallFunction(self, FunctionName: str, *FunctionArguments) -> dict:
        Txn = {"value": 0, "gas": self.Instance.functions[FunctionName](*FunctionArguments).estimateGas()}
        TransactionData = self.Instance.functions[FunctionName](*FunctionArguments).buildTransaction(Txn)
        logger.info(f"\n[CallFunction]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[Value]{TransactionData['value']} [Gas]{TransactionData['gas']}")
        TransactionReceipt = self.Account.SendTransaction(self.Address, TransactionData["data"], TransactionData["value"], TransactionData["gas"])
        return TransactionReceipt

    def EncodeABI(self, FunctionName: str, *FunctionArguments) -> str:
        CallData = self.Instance.encodeABI(fn_name=FunctionName, args=FunctionArguments)
        return CallData

    @staticmethod
    def SolidityToABIAndBytecode(Course: str, ContractName: str) -> tuple:
        with open(Course, "r", encoding="utf-8") as sol:
            CompiledSol = compile_source(sol.read())
        ContractData = CompiledSol[f'<stdin>:{ContractName}']
        ABI = ContractData['abi']
        Bytecode = ContractData['bin']
        with open(f'{ContractName}.json', 'w') as f:
            json.dump((ABI, Bytecode), f)
        logger.info(f"\n[CompileContract]\n[Course]{Course}\n[ContractName]{ContractName}\n[ABI]{ABI}\n[Bytecode]{Bytecode}")
        return (ABI, Bytecode)


'''
Web3.keccak()
Web3.solidityKeccak()
web3.constants.ADDRESS_ZERO
web3.constants.HASH_ZERO
web3.constants.WEI_PER_ETHER
web3.constants.MAX_INT
'''
