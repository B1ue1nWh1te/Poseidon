from Poseidon.Blockchain import *

RPCUrl = "https://rpc.sepolia.org"

chain = Chain(RPCUrl)

chain.GetBasicInformation()

chain.GetTransactionInformationByBlockIdAndIndex("latest", 0)

chain.GetBlockInformation(1)

chain.GetBalance("0x0000000000000000000000000000000000000000")

Address, PrivateKey = BlockchainUtils.CreateNewAccount()

input("Waiting for claim some testETH ...")

account = Account(chain, PrivateKey)

account.RequestAuthorizationBeforeSendTransaction()

TransactionHash = account.Transfer("0x0000000000000000000000000000000000000000", 1, "0x1234", BlockchainUtils.GweiToWei(10), 30000)["TransactionHash"]

chain.GetPublicKeyByTransactionHash(TransactionHash)

BlockchainUtils.RecoverRawTransaction("0xf86d820144843b9aca0082520894b78777860637d56543da23312c7865024833f7d188016345785d8a0000802ba0e2539a5d9f056d7095bd19d6b77b850910eeafb71534ebd45159915fab202e91a007484420f3968697974413fc55d1142dc76285d30b1b9231ccb71ed1e720faae")

chain.GetTransactionInformationByHash(TransactionHash)

account.SendTransaction("0x0000000000000000000000000000000000000000", "0xdeadbeef")

account.SendTransactionByEIP1559("0x0000000000000000000000000000000000000000", "0xdeadbeef")

BlockchainUtils.SwitchSolidityVersion("0.8.19")

abi, bytecode = BlockchainUtils.Compile("test.sol", "Test")

contract = account.DeployContract(abi, bytecode, 0, None, "testtesttest")["Contract"]

chain.GetCode(contract.Address)

chain.GetStorage(contract.Address, 0)

chain.DumpStorage(contract.Address, 3)

account.DeployContractWithoutABI(bytecode)

SignatureData = account.SignMessage("test")

BlockchainUtils.SignatureToRSV(SignatureData["Signature"])

BlockchainUtils.RSVToSignature(SignatureData["R"], SignatureData["S"], hex(SignatureData["V"]))

BlockchainUtils.RecoverMessage("test", SignatureData["Signature"])

BlockchainUtils.RecoverMessageHash(SignatureData["MessageHash"], SignatureData["Signature"])

account.SignMessageHash(SignatureData["MessageHash"])

contract.ReadOnlyCallFunction("readTest")

InputData = contract.CallFunction("writeTest", "000000")["InputData"]

contract.CallFunctionWithParameters(0, BlockchainUtils.GweiToWei(10), 100000, "writeTest", "111111")

contract.DecodeFunctionInputData(InputData)

contract.ReadOnlyCallFunction("readTest")

contract.EncodeABI("writeTest", "222222")

BlockchainUtils.GetFunctionSelector("writeTest", ["string"])

BlockchainUtils.GetContractAddressByCREATE(Address, 3)

BlockchainUtils.GetContractAddressByCREATE2(contract.Address, "42", bytecode)

Assembly = """
PUSH1 0x0a
PUSH1 0X0c
PUSH1 0x00
CODECOPY
PUSH1 0X0a
PUSH1 0X00
RETURN

PUSH1 0x2a
PUSH1 0x80
MSTORE
PUSH1 0x20
PUSH1 0x80
RETURN
"""

Bytecode = BlockchainUtils.AssemblyToBytecode(Assembly)

BlockchainUtils.BytecodeToAssembly(Bytecode)

# BlockchainUtils.MnemonicToAddressAndPrivateKey("test test test test test test test test test test test test")

# BlockchainUtils.CrackSelector("transferFrom", ["address", "address", "uint256"],["address","bytes32"])
