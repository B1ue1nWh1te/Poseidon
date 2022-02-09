from loguru import logger
from web3 import Web3, HTTPProvider, EthereumTesterProvider
from web3.middleware import geth_poa_middleware
from Crypto.Util.number import bytes_to_long
from solcx import compile_source
import json


'''
-----template-----
from Poseidon_Blockchain import *
from loguru import logger
import solcx

SolidityVersion = solcx.install_solc('')
solcx.set_solc_version(SolidityVersion)
logger.log(f"Solidity Version:{SolidityVersion}")

chain = Chain("")
account = Account(chain, "0x")
contractAddress = Web3.toChecksumAddress("")

abi, bytecode = SolidityToAbiAndBytecode(".sol", "")
contract = chain.Net.eth.contract(address=contractAddress, abi=abi)
transactionData = contract.functions.functionName(params).buildTransaction()
transactionReceipt = account.SendTransactionToChain(transactionData["to"], transactionData["data"])

arg1 = contract.encodeABI(fn_name="functionName")
arg2 = contract.encodeABI(fn_name="functionName", args=[arg1])
transactionData = contract.functions.functionName(arg1, arg2).buildTransaction({'value': 0})
transactionReceipt = account.SendTransactionToChain(transactionData["to"], transactionData["data"], transactionData["value"])

logger.success("Execution completed.")
-----template-----

from solcx import install_solc; install_solc(version='latest')

Contract.functions.Function1(params).transact()  # [!Bug]ToChain 
Contract.functions.Function2().call()   # Local

Web3.toHex()
Web3.toText()
Web3.toBytes()
Web3.toInt()
Web3.toJSON()
Web3.isAddress()
Web3.keccak()
Web3.solidityKeccak()

web3.geth.miner.set_extra(str)
web3.geth.miner.start(int)
web3.geth.miner.stop()
web3.constants.ADDRESS_ZERO
web3.constants.HASH_ZERO
web3.constants.WEI_PER_ETHER
web3.constants.MAX_INT
'''


class Chain():
    def __init__(self, RPCUrl: str) -> None:
        # Net = Web3(EthereumTesterProvider())
        Net = Web3(HTTPProvider(RPCUrl))
        if Net.isConnected():
            logger.success(f"\n[ConnectToChain]Successfully connected to [{RPCUrl}].")
            self.Net = Net
            self.Net.middleware_onion.inject(geth_poa_middleware, layer=0)
            self.ShowBasicInformation()
            self.ShowBlockInformation()
        else:
            logger.error(f"\n[ConnectToChain]Failed to connect to [{RPCUrl}].")
            self.Net = None

    def ShowBasicInformation(self) -> None:
        ClientVersion = self.Net.clientVersion
        ChainId = self.Net.eth.chainId
        BlockNumber = self.Net.eth.block_number
        PeerCount = self.Net.net.peer_count
        logger.info(f"\n[BasicInformation]\n[ClientVersion]{ClientVersion}\n[ChainId]{ChainId}\n[BlockNumber]{BlockNumber}\n[PeerCount]{PeerCount}")

    def ShowBlockInformation(self, BlockId="latest") -> None:
        Data = self.Net.eth.get_block(BlockId)
        BlockNumber = Data["number"]
        TimeStamp = Data["timestamp"]
        CoinBase = Data["miner"]
        TransactionCount = len(Data["transactions"])
        # TransactionHashs = [hex(bytes_to_long(bytes(i))) for i in Data["transactions"]]
        ExtraData = Data.get("extraData", "None")
        ProofOfAuthorityData = Data.get("proofOfAuthorityData", "None")
        logger.info(
            f"\n[BlockInformation][{BlockId}]\n[BlockNumber]{BlockNumber}\n[TimeStamp]{TimeStamp}\n[CoinBase]{CoinBase}\n[TransactionCount]{TransactionCount}\n[ExtraData]{ExtraData}\n[ProofOfAuthorityData]{ProofOfAuthorityData}")

    def ShowTransactionByHash(self, TransactionHash: str) -> None:
        Data = self.Net.eth.get_transaction(TransactionHash)
        BlockNumber = Data["blockNumber"]
        TransactionIndex = Data["transactionIndex"]
        From = Data["from"]
        To = Data["to"]
        InputData = Data["input"]
        Value = Data["value"]
        logger.info(f"\n[TransactionInformation][{TransactionHash}]\n[BlockNumber]{BlockNumber}\n[TransactionIndex]{TransactionIndex}\n[From]{From}\n[To]{To}\n[InputData]{InputData}\n[Value]{Value}")

    def ShowTransactionByBlockIdAndIndex(self, BlockId, TransactionId: int) -> None:
        Data = self.Net.eth.get_transaction_by_block(BlockId, TransactionId)
        BlockNumber = Data["blockNumber"]
        TransactionIndex = Data["transactionIndex"]
        From = Data["from"]
        To = Data["to"]
        InputData = Data["input"]
        Value = Data["value"]
        logger.info(
            f"\n[TransactionInformation][{BlockId}][{TransactionId}]\n[BlockNumber]{BlockNumber}\n[TransactionIndex]{TransactionIndex}\n[From]{From}\n[To]{To}\n[InputData]{InputData}\n[Value]{Value}")

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
        logger.info(f"\n[Storage][{Address}][{Index}]\n[Hex]{DataHex}---[Dec]{Data}")
        return Data

    def DumpStorage(self, Address: str, Count: int) -> list:
        Data = [hex(bytes_to_long(self.Net.eth.get_storage_at(Address, i))) for i in range(Count)]
        Temp = '\n'.join(Data)
        logger.info(f"\n[Storage][{Address}][0~{Count-1}]\n{Temp}")
        return Data


class Account():
    def __init__(self, Chain: Chain, PrivateKey: str) -> None:
        try:
            self.Chain = Chain
            self.Net = Chain.Net
            Account = self.Net.eth.account.from_key(PrivateKey)
            self.Address = Web3.toChecksumAddress(Account.address)
            self.PrivateKey = Account.privateKey
            self.Net.eth.default_account = self.Address
            logger.success(f"\n[ImportAccount]Successfully import account.\n[Address]{self.Address}")
        except:
            logger.error(f"\n[ImportAccount]Failed to import through the private key of [{PrivateKey}].")

    def GetSelfBalance(self) -> int:
        Balance = self.Chain.GetBalanceByAddress(self.Address)
        return Balance

    def SendTransactionToChain(self, To: str, Data: str, Value=0, Gas=1000000) -> dict:
        Txn = {
            "from": self.Address,
            "to": Web3.toChecksumAddress(To),
            "gasPrice": self.Net.eth.max_priority_fee * 2,
            "gas": int(Gas),
            "nonce": self.Net.eth.get_transaction_count(self.Address),
            "value": int(Value),
            "data": Data,
            "chainId": self.Net.eth.chainId
        }
        SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
        TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
        logger.info(f"\n[SendTransaction]\n[TransactionHash]{TransactionHash}\n[Txn]{Txn}")
        TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=180)
        logger.success(f"\n[ConfirmTransaction]\n[TransactionHash]{TransactionHash}\n[TransactionReceipt]{TransactionReceipt}")
        return TransactionReceipt

    def DeployContractToChain(self, Abi: dict, Bytecode: str, Value=0) -> str:
        Contract = self.Net.eth.contract(abi=Abi, bytecode=Bytecode)
        # logger.info(f"\n[DeployContract]\n[Abi]{Abi}\n[Bytecode]{Bytecode}")
        TransactionData = Contract.constructor().buildTransaction({"value": Value})
        Txn = {
            "from": self.Address,
            "gasPrice": self.Net.eth.max_priority_fee * 2,
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
        Contract = self.Net.eth.contract(address=ContractAddress, abi=Abi)
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


def SolidityToAbiAndBytecode(Course: str, ContractName: str) -> tuple:
    with open(Course, "r", encoding="utf-8") as sol:
        CompiledSol = compile_source(sol.read())
    ContractData = CompiledSol[f'<stdin>:{ContractName}']
    Abi = ContractData['abi']
    Bytecode = ContractData['bin']
    with open(f'{ContractName}.json', 'w') as json:
        json.dump((Abi, Bytecode), json)
    logger.info(f"\n[CompileContract]\n[Abi]{Abi}\n[Bytecode]{Bytecode}")
    return (Abi, Bytecode)
