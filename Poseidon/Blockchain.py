from web3 import Web3
from loguru import logger
from sys import exc_info
from json import dumps


class Chain():
    def __init__(self, RPCUrl: str, RequestParams: dict = None):
        from web3 import HTTPProvider
        from web3.middleware import geth_poa_middleware
        from time import time

        StartTime = time()
        self.Net = Web3(HTTPProvider(RPCUrl, request_kwargs=RequestParams))
        if self.Net.isConnected():
            FinishTime = time()
            Delay = round((FinishTime - StartTime) * 1000)
            logger.success(f"\n[ConnectToChain]Successfully connected to [{RPCUrl}]. [Delay] {Delay} ms")
            self.Net.middleware_onion.inject(geth_poa_middleware, layer=0)
            self.GetBasicInformation()
        else:
            logger.error(f"\n[ConnectToChain]Failed to connect to [{RPCUrl}].")
            raise Exception("Failed to connect to chain.")

    def GetBasicInformation(self) -> dict:
        try:
            ChainId = self.Net.eth.chainId
            BlockNumber = self.Net.eth.block_number
            GasPrice = Web3.fromWei(self.Net.eth.gas_price, "gwei")
            ClientVersion = self.Net.clientVersion
            logger.success(f"\n[BasicInformation]\n[ChainId]{ChainId}\n[BlockNumber]{BlockNumber}\n[GasPrice]{GasPrice} Gwei\n[ClientVersion]{ClientVersion}")
            return {"ChainId": ChainId, "BlockNumber": BlockNumber, "GasPrice": GasPrice, "ClientVersion": ClientVersion}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[BasicInformation]Failed to get basic information.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def GetBlockInformation(self, BlockID="latest") -> dict:
        try:
            Info = self.Net.eth.get_block(BlockID)
            BlockHash = Info.hash.hex()
            BlockNumber = Info.number
            BlockTimeStamp = Info.timestamp
            BlockTransactionAmount = len(Info.transactions)
            logger.success(f"\n[BlockInformation][{BlockID}]\n[Hash]{BlockHash}\n[Number]{BlockNumber}\n[TimeStamp]{BlockTimeStamp}\n[TransactionAmount]{BlockTransactionAmount}")
            return {"BlockID": BlockID, "BlockHash": BlockHash, "BlockNumber": BlockNumber, "BlockTimeStamp": BlockTimeStamp, "BlockTransactionAmount": BlockTransactionAmount}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[BlockInformation]Failed to get block [{BlockID}] information.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def GetTransactionByHash(self, TransactionHash: str) -> dict:
        try:
            Info = self.Net.eth.get_transaction(TransactionHash)
            BlockNumber = Info.blockNumber
            TransactionIndex = Info.transactionIndex
            From = Info["from"]
            To = Info.to
            GasPrice = Info.gasPrice
            Gas = Info.gas
            Nonce = Info.nonce
            Value = Info.value
            InputData = Info.input
            if GasPrice != None:
                TransactionType = "Traditional"
                GasPrice = Web3.fromWei(GasPrice, "gwei")
                logger.info(
                    f"\n[TransactionInformation][{TransactionHash}]\n[TransactionType]{TransactionType}\n[BlockNumber]{BlockNumber} [TransactionIndex]{TransactionIndex}\n[From]{From}\n[To]{To}\n[GasPrice]{GasPrice} Gwei [Gas]{Gas}\n[Nonce]{Nonce} [Value]{Value}\n[InputData]{InputData}")
                return {"TransactionHash": TransactionHash, "TransactionType": TransactionType, "BlockNumber": BlockNumber, "TransactionIndex": TransactionIndex, "From": From, "To": To, "GasPrice": GasPrice, "Gas": Gas, "Nonce": Nonce, "Value": Value, "InputData": InputData}
            else:
                TransactionType = "EIP-1559"
                MaxFeePerGas = Web3.fromWei(Info.maxFeePerGas, "gwei")
                MaxPriorityFeePerGas = Web3.fromWei(Info.maxPriorityFeePerGas, "gwei")
                logger.info(
                    f"\n[TransactionInformation][{TransactionHash}]\n[TransactionType]{TransactionType}\n[BlockNumber]{BlockNumber} [TransactionIndex]{TransactionIndex}\n[From]{From}\n[To]{To}\n[MaxFeePerGas]{MaxFeePerGas} Gwei\n[MaxPriorityFeePerGas]{MaxPriorityFeePerGas} Gwei\n[Nonce]{Nonce} [Value]{Value} [Gas]{Gas}\n[InputData]{InputData}")
                return {"TransactionHash": TransactionHash, "TransactionType": TransactionType, "BlockNumber": BlockNumber, "TransactionIndex": TransactionIndex, "From": From, "To": To, "MaxFeePerGas": MaxFeePerGas, "MaxPriorityFeePerGas": MaxPriorityFeePerGas, "Nonce": Nonce, "Value": Value, "Gas": Gas, "InputData": InputData}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[TransactionInformation]Failed to get transaction [{TransactionHash}] information.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def GetTransactionByBlockIdAndIndex(self, BlockID, TransactionIndex: int) -> dict:
        try:
            Info = self.Net.eth.get_transaction_by_block(BlockID, TransactionIndex)
            BlockNumber = Info.blockNumber
            TransactionHash = Info.hash.hex()
            From = Info["from"]
            To = Info.to
            GasPrice = Info.gasPrice
            Gas = Info.gas
            Nonce = Info.nonce
            Value = Info.value
            InputData = Info.input
            if GasPrice != None:
                TransactionType = "Traditional"
                GasPrice = Web3.fromWei(GasPrice, "gwei")
                logger.info(
                    f"\n[TransactionInformation][{BlockID}][{TransactionIndex}]\n[TransactionType]{TransactionType}\n[BlockNumber]{BlockNumber} [TransactionIndex]{TransactionIndex}\n[From]{From}\n[To]{To}\n[GasPrice]{GasPrice} Gwei [Gas]{Gas}\n[Nonce]{Nonce} [Value]{Value}\n[InputData]{InputData}")
                return {"TransactionHash": TransactionHash, "TransactionType": TransactionType, "BlockNumber": BlockNumber, "TransactionIndex": TransactionIndex, "From": From, "To": To, "GasPrice": GasPrice, "Gas": Gas, "Nonce": Nonce, "Value": Value, "InputData": InputData}
            else:
                TransactionType = "EIP-1559"
                MaxFeePerGas = Web3.fromWei(Info.maxFeePerGas, "gwei")
                MaxPriorityFeePerGas = Web3.fromWei(Info.maxPriorityFeePerGas, "gwei")
                logger.info(
                    f"\n[TransactionInformation][{BlockID}][{TransactionIndex}]\n[TransactionType]{TransactionType}\n[BlockNumber]{BlockNumber} [TransactionIndex]{TransactionIndex}\n[From]{From}\n[To]{To}\n[MaxFeePerGas]{MaxFeePerGas} Gwei\n[MaxPriorityFeePerGas]{MaxPriorityFeePerGas} Gwei\n[Nonce]{Nonce} [Value]{Value} [Gas]{Gas}\n[InputData]{InputData}")
                return {"TransactionHash": TransactionHash, "TransactionType": TransactionType, "BlockNumber": BlockNumber, "TransactionIndex": TransactionIndex, "From": From, "To": To, "MaxFeePerGas": MaxFeePerGas, "MaxPriorityFeePerGas": MaxPriorityFeePerGas, "Nonce": Nonce, "Value": Value, "Gas": Gas, "InputData": InputData}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[TransactionInformation]Failed to get transaction [{BlockID}][{TransactionIndex}] information.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def GetBalance(self, Address: str) -> int:
        try:
            Balance = self.Net.eth.get_balance(Address)
            logger.success(f"\n[GetBalance][{Address}]\n[{Balance} Wei]<=>[{Web3.fromWei(Balance,'ether')} Ether]")
            return Balance
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[GetBalance]Failed to get [{Address}] balance.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def GetCode(self, Address: str) -> str:
        try:
            Code = self.Net.eth.get_code(Address).hex()
            logger.success(f"\n[GetCode][{Address}]\n[Code]{Code}")
            return Code
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[GetCode]Failed to get [{Address}] code.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def GetStorage(self, Address: str, Index: int) -> str:
        try:
            Data = self.Net.eth.get_storage_at(Address, Index).hex()
            logger.success(f"\n[GetStorage][{Address}][{Index}]\n[Hex][{Data}]<=>[Dec][{int(Data,16)}]")
            return Data
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[GetStorage]Failed to get [{Address}][{Index}] storage.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def DumpStorage(self, Address: str, Count: int) -> list:
        try:
            Data = [self.Net.eth.get_storage_at(Address, i).hex() for i in range(Count)]
            Temp = '\n'.join(Data)
            logger.info(f"\n[DumpStorage][{Address}][slot 0 ... {Count-1}]\n{Temp}")
            return Data
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[DumpStorage]Failed to dump [{Address}][0-{Count-1}] storages.\n[ExceptionInformation]{ExceptionInformation}")
            return None


class Account():
    def __init__(self, Chain: Chain, PrivateKey: str):
        try:
            self.Chain = Chain
            self.Net = Chain.Net
            AccountTemp = self.Net.eth.account.from_key(PrivateKey)
            self.Address = Web3.toChecksumAddress(AccountTemp.address)
            self.PrivateKey = AccountTemp.privateKey
            self.Net.eth.default_account = self.Address
            logger.success(f"\n[ImportAccount]Successfully import account [{self.Address}].")
            self.GetSelfBalance()
        except:
            ExceptionInformation = exc_info()
            logger.error(f"\n[ImportAccount]Failed to import account.\n[ExceptionInformation]{ExceptionInformation}")
            raise Exception("Failed to import account.")

    def GetSelfBalance(self) -> int:
        Balance = self.Chain.GetBalance(self.Address)
        if Balance == 0:
            logger.warning(f"\n[GetSelfBalance]Warning: This account's balance is insufficient to pay transactions fee.")
        return Balance

    def SendTransaction(self, To: str, Data: str, Value: int = 0, Gas: int = 10000000) -> dict:
        try:
            Txn = {
                "chainId": self.Net.eth.chainId,
                "from": self.Address,
                "to": Web3.toChecksumAddress(To),
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "value": Value,
                "gasPrice": round(self.Net.eth.gas_price * 1.2),
                "gas": Gas,
                "data": Data,
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            Txn["gasPrice"] = f'{Web3.fromWei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[SendTransaction][Traditional]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}")
            TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=120)
            Status = TransactionReceipt.status
            if Status:
                BlockNumber = TransactionReceipt.blockNumber
                GasUsed = TransactionReceipt.gasUsed
                Logs = TransactionReceipt.logs
                logger.success(f"\n[ConfirmTransaction][Traditional][Success]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[GasUsed]{GasUsed}\n[Logs]{Logs}")
                return {"Status": Status, "TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "GasUsed": GasUsed, "Logs": Logs}
            else:
                logger.error(f"\n[ConfirmTransaction][Traditional][Fail]\n[TransactionHash]{TransactionHash}")
                return {"Status": Status, "TransactionHash": TransactionHash}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[SendTransaction][Traditional]Failed to send transaction.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def SendTransactionByEIP1559(self, To: str, Data: str, Value: int = 0, Gas: int = 1000000) -> dict:
        try:
            Txn = {
                "chainId": self.Net.eth.chainId,
                "from": self.Address,
                "to": Web3.toChecksumAddress(To),
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "value": Value,
                "maxFeePerGas": self.Net.eth.max_priority_fee * 2,
                "maxPriorityFeePerGas": round(self.Net.eth.max_priority_fee * 1.2),
                "gas": Gas,
                "data": Data
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            Txn["gasPrice"] = f'{Web3.fromWei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[SendTransaction][EIP-1559]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}")
            TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=120)
            Status = TransactionReceipt.status
            if Status:
                BlockNumber = TransactionReceipt.blockNumber
                GasUsed = TransactionReceipt.gasUsed
                Logs = TransactionReceipt.logs
                logger.success(f"\n[ConfirmTransaction][EIP-1559][Success]\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[GasUsed]{GasUsed}\n[Logs]{Logs}")
                return {"Status": Status, "TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "GasUsed": GasUsed, "Logs": Logs}
            else:
                logger.error(f"\n[ConfirmTransaction][EIP-1559][Fail]\n[TransactionHash]{TransactionHash}")
                return {"Status": Status, "TransactionHash": TransactionHash}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[SendTransaction][EIP-1559]Failed to send transaction.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def DeployContract(self, ABI: dict, Bytecode: str, Value: int = 0, *Arguments) -> dict:
        try:
            DeployingContract = self.Net.eth.contract(abi=ABI, bytecode=Bytecode)
            TransactionData = DeployingContract.constructor(*Arguments).buildTransaction({"value": Value})
            Txn = {
                "chainId": self.Net.eth.chainId,
                "from": self.Address,
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "value": TransactionData["value"],
                "gasPrice": round(self.Net.eth.gas_price * 1.2),
                "gas": TransactionData["gas"],
                "data": TransactionData["data"]
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            logger.info(f"\n[DeployContract][Traditional]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}")
            TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=120)
            Status = TransactionReceipt.status
            if Status:
                ContractAddress = TransactionReceipt.contractAddress
                BlockNumber = TransactionReceipt.blockNumber
                GasUsed = TransactionReceipt.gasUsed
                Logs = TransactionReceipt.logs
                logger.success(f"\n[ConfirmDeploy][Success]\n[ContractAddress]{ContractAddress}\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[GasUsed]{GasUsed}\n[Logs]{Logs}")
                DeployedContract = Contract(self, ContractAddress, ABI)
                return {"Status": Status, "TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "GasUsed": GasUsed, "Logs": Logs, "ContractAddress": ContractAddress, "Contract": DeployedContract}
            else:
                logger.error(f"\n[ConfirmDeploy][Fail]\n[TransactionHash]{TransactionHash}")
                return {"Status": Status, "TransactionHash": TransactionHash}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[DeployContract][Traditional]Failed to deploy contract.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def DeployContractByEIP1559(self, ABI: dict, Bytecode: str, Value: int = 0, *Arguments) -> dict:
        try:
            DeployingContract = self.Net.eth.contract(abi=ABI, bytecode=Bytecode)
            TransactionData = DeployingContract.constructor(*Arguments).buildTransaction({"value": Value})
            Txn = {
                "chainId": self.Net.eth.chainId,
                "from": self.Address,
                "nonce": self.Net.eth.get_transaction_count(self.Address),
                "value": TransactionData["value"],
                "maxFeePerGas": self.Net.eth.max_priority_fee * 2,
                "maxPriorityFeePerGas": round(self.Net.eth.max_priority_fee * 1.2),
                "gas": TransactionData["gas"],
                "data": TransactionData["data"]
            }
            SignedTxn = self.Net.eth.account.sign_transaction(Txn, self.PrivateKey)
            TransactionHash = self.Net.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            logger.info(f"\n[DeployContract][EIP-1559]\n[TransactionHash]{TransactionHash}\n[Txn]{dumps(Txn, indent=2)}")
            TransactionReceipt = self.Net.eth.wait_for_transaction_receipt(TransactionHash, timeout=120)
            Status = TransactionReceipt.status
            if Status:
                ContractAddress = TransactionReceipt.contractAddress
                BlockNumber = TransactionReceipt.blockNumber
                GasUsed = TransactionReceipt.gasUsed
                Logs = TransactionReceipt.logs
                logger.success(f"\n[ConfirmDeploy][Success]\n[ContractAddress]{ContractAddress}\n[TransactionHash]{TransactionHash}\n[BlockNumber]{BlockNumber}\n[GasUsed]{GasUsed}\n[Logs]{Logs}")
                DeployedContract = Contract(self, ContractAddress, ABI)
                return {"Status": Status, "TransactionHash": TransactionHash, "BlockNumber": BlockNumber, "GasUsed": GasUsed, "Logs": Logs, "ContractAddress": ContractAddress, "Contract": DeployedContract}
            else:
                logger.error(f"\n[ConfirmDeploy][Fail]\n[TransactionHash]{TransactionHash}")
                return {"Status": Status, "TransactionHash": TransactionHash}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[DeployContract][EIP-1559]Failed to deploy contract.\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def SignMessage(self, Message: str) -> dict:
        from eth_account.messages import encode_defunct
        try:
            Temp = encode_defunct(text=Message)
            SignedMessage = self.Net.eth.account.sign_message(Temp, private_key=self.PrivateKey)
            SignedMessageHash = SignedMessage.messageHash.hex()
            SignedMessageSignature = SignedMessage.signature.hex()
            SignedMessageR = hex(SignedMessage.r)
            SignedMessageS = hex(SignedMessage.s)
            SignedMessageV = SignedMessage.v
            logger.success(
                f"\n[SignMessage][{self.Address}]\n[Message]{Message}\n[SignedMessageHash]{SignedMessageHash}\n[SignedMessageSignature]{SignedMessageSignature}\n[SignedMessageR]{SignedMessageR}\n[SignedMessageS]{SignedMessageS}\n[SignedMessageV]{SignedMessageV}")
            return {"Address": self.Address, "Message": Message, "SignedMessageHash": SignedMessageHash, "SignedMessageSignature": SignedMessageSignature, "SignedMessageR": SignedMessageR, "SignedMessageS": SignedMessageS, "SignedMessageV": SignedMessageV}
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[SignMessage]Failed to sign messge [{Message}] by account [{self.Address}].\n[ExceptionInformation]{ExceptionInformation}")
            return None


class Contract():
    def __init__(self, Account: Account, Address: str, ABI: dict):
        try:
            self.Account = Account
            self.Net = Account.Net
            self.Address = Web3.toChecksumAddress(Address)
            self.Instance = self.Net.eth.contract(address=self.Address, abi=ABI)
            logger.success(f"\n[InstantiateContract]Successfully instantiated contract [{self.Address}].")
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[InstantiateContract]Failed to instantiated contract [{self.Address}].\n[ExceptionInformation]{ExceptionInformation}")
            raise Exception("Failed to instantiate contract.")

    def CallFunction(self, Value: int, FunctionName: str, *FunctionArguments) -> dict:
        TransactionData = self.Instance.functions[FunctionName](*FunctionArguments).buildTransaction({"value": Value})
        logger.info(f"\n[CallFunction][Traditional][{self.Address}]\n[Function]{FunctionName}{FunctionArguments}\n[Value]{TransactionData['value']} [Gas]{TransactionData['gas']}")
        TransactionResult = self.Account.SendTransaction(self.Address, TransactionData["data"], TransactionData["value"], TransactionData["gas"])
        return TransactionResult

    def CallFunctionByEIP1559(self, Value: int, FunctionName: str, *FunctionArguments) -> dict:
        TransactionData = self.Instance.functions[FunctionName](*FunctionArguments).buildTransaction({"value": Value})
        logger.info(f"\n[CallFunction][EIP-1559][{self.Address}]\n[Function]{FunctionName}{FunctionArguments}\n[Value]{TransactionData['value']} [Gas]{TransactionData['gas']}")
        TransactionResult = self.Account.SendTransactionByEIP1559(self.Address, TransactionData["data"], TransactionData["value"], TransactionData["gas"])
        return TransactionResult

    def ReadOnlyCallFunction(self, FunctionName: str, *FunctionArguments):
        try:
            Result = self.Instance.functions[FunctionName](*FunctionArguments).call()
            logger.success(f"\n[CallFunction][ReadOnly][{self.Address}]\n[Function]{FunctionName}{FunctionArguments}\n[Result]{Result}")
            return Result
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[CallFunction][ReadOnly]Failed to call readonly function [{FunctionName}{FunctionArguments}].\n[ExceptionInformation]{ExceptionInformation}")
            return None

    def EncodeABI(self, FunctionName: str, *FunctionArguments) -> str:
        try:
            CallData = self.Instance.encodeABI(fn_name=FunctionName, args=FunctionArguments)
            logger.success(f"\n[EncodeABI]Success.\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[CallData]{CallData}")
            return CallData
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[EncodeABI]Failed to encode abi for [{FunctionName}{FunctionArguments}].\n[ExceptionInformation]{ExceptionInformation}")
            return None


class BlockchainUtils():
    @staticmethod
    def SwitchSolidityVersion(SolidityVersion: str):
        from solcx import install_solc, set_solc_version
        try:
            install_solc(SolidityVersion)
            set_solc_version(SolidityVersion)
            logger.success(f"\n[SwitchSolidityVersion]Current Version:{SolidityVersion}")
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[SwitchSolidityVersion]Failed to switch to version [{SolidityVersion}].\n[ExceptionInformation]{ExceptionInformation}")
            raise Exception("Failed to switch solidity version.")

    @staticmethod
    def Compile(FileCourse: str, ContractName: str, AllowPaths: str = None) -> tuple:
        from solcx import compile_source
        from json import dump
        try:
            with open(FileCourse, "r", encoding="utf-8") as sol:
                CompiledSol = compile_source(sol.read(), allow_paths=AllowPaths, optimize=True)
            ContractData = CompiledSol[f'<stdin>:{ContractName}']
            ABI = ContractData['abi']
            Bytecode = ContractData['bin']
            with open(f'{ContractName}_ABI.json', 'w') as f:
                dump(ABI, f, indent=4)
            logger.success(f"\n[CompileContract]Success.\n[FileCourse]{FileCourse}\n[ContractName]{ContractName}\n[ABI]{ABI}\n[Bytecode]{Bytecode}")
            return (ABI, Bytecode)
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[CompileContract]Failed to compile the contract [{FileCourse}][{ContractName}].\n[ExceptionInformation]{ExceptionInformation}")
            raise Exception("Failed to compile the contract.")

    @staticmethod
    def CreateNewAccount() -> tuple:
        from Crypto.Util.number import bytes_to_long
        Net = Web3()
        Keys = Net.eth.account.create()
        Address = Net.toChecksumAddress(Keys.address)
        PrivateKey = hex(bytes_to_long(Keys.privateKey))
        logger.success(f"\n[CreateNewAccount]\n[Address]{Address}\n[PrivateKey]{PrivateKey}")
        return (Address, PrivateKey)

    @staticmethod
    def RecoverMessage(Message: str, Signature: str) -> str:
        from eth_account.messages import encode_defunct
        try:
            Net = Web3()
            Temp = encode_defunct(text=Message)
            Signer = Net.eth.account.recover_message(Temp, signature=Signature)
            logger.success(f"\n[RecoverMessage]\n[Message]{Message}\n[Signature]{Signature}\n[Signer]{Signer}")
            return Signer
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[RecoverMessage]Failed to recover message [{Message}] with [{Signature}].\n[ExceptionInformation]{ExceptionInformation}")
            return None

    @staticmethod
    def RecoverMessageByHash(MessageHash: str, Signature: str) -> str:
        try:
            Net = Web3()
            Signer = Net.eth.account.recoverHash(MessageHash, signature=Signature)
            logger.success(f"\n[RecoverMessageByHash]\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[Signer]{Signer}")
            return Signer
        except Exception:
            ExceptionInformation = exc_info()
            logger.error(f"\n[RecoverMessageByHash]Failed to recover message hash [{MessageHash}] with [{Signature}].\n[ExceptionInformation]{ExceptionInformation}")
            return None
