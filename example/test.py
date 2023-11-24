from Poseidon.Blockchain import *

# RPCUrl = "https://rpc.ankr.com/eth_goerli"

RPCUrl = "https://rpc.ankr.com/eth_sepolia"

# RPCUrl = "https://rpc.ankr.com/polygon_mumbai"

# RPCUrl = "https://rpc.ankr.com/scroll_sepolia_testnet"

chain = Chain(RPCUrl)

chain.GetBasicInformation()

chain.GetTransactionInformationByBlockIdAndIndex("latest", 0)

chain.GetBlockInformation(1)

chain.GetBalance("0x0000000000000000000000000000000000000000")

Address, PrivateKey = BlockchainUtils.CreateNewAccount()

input(f"Waiting for sending some testETH to [{Address}] ...")

account = Account(chain, PrivateKey)

SignatureData = account.SignMessage("test")

account.SignMessageHash(SignatureData.MessageHash)

account.RequestAuthorizationBeforeSendTransaction()

TransactionHash = account.Transfer("0x0000000000000000000000000000000000000000", 1, "0x1234", BlockchainUtils.GweiToWei(10), 50000).TransactionHash

chain.GetPublicKeyByTransactionHash(TransactionHash)

chain.GetTransactionInformationByHash(TransactionHash)

account.SendTransaction("0x0000000000000000000000000000000000000000", "0xdeadbeef")

account.SendTransactionByEIP1559("0x0000000000000000000000000000000000000000", "0xdeadbeef")

BlockchainUtils.SwitchSolidityVersion("0.8.23")

abi, bytecode = BlockchainUtils.Compile("Test.sol", "Test", "0.8.23", True, 100000, "./", "./", "shanghai")

abi = BlockchainUtils.ImportABI("TestABI.json")

contract: Contract = account.DeployContract(abi, bytecode, 0, None, "test0").Contract

chain.GetCode(contract.Address)

chain.GetStorage(contract.Address, 0)

chain.DumpStorage(contract.Address, 3)

account.DeployContractWithoutABI(
    bytecode+"000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000057465737430000000000000000000000000000000000000000000000000000000")

contract.ReadOnlyCallFunction("readTest")

InputData = contract.CallFunction("writeTest", "test1").InputData

contract.CallFunctionWithParameters(0, BlockchainUtils.GweiToWei(10), 100000, "writeTest", "test2")

contract.DecodeFunctionInputData(InputData)

contract.ReadOnlyCallFunction("readTest")

contract.EncodeABI("writeTest", "test3")

BlockchainUtils.GetFunctionSelector("writeTest", ["string"])

BlockchainUtils.GetContractAddressByCREATE(Address, 3)

BlockchainUtils.GetContractAddressByCREATE2(contract.Address, "42", bytecode)

BlockchainUtils.SignatureToRSV(SignatureData.Signature)

BlockchainUtils.RSVToSignature(SignatureData.R, SignatureData.S, SignatureData.V)

BlockchainUtils.RecoverMessage("test", SignatureData.Signature)

BlockchainUtils.RecoverMessageHash(SignatureData.MessageHash, SignatureData.Signature)

print(BlockchainUtils.WeiToGwei(1000000000))
print(BlockchainUtils.FromWei(1000000000, 'ether'))
print(BlockchainUtils.ToWei(1, 'ether'))

BlockchainUtils.RecoverRawTransaction(
    "0xf86d820144843b9aca0082520894b78777860637d56543da23312c7865024833f7d188016345785d8a0000802ba0e2539a5d9f056d7095bd19d6b77b850910eeafb71534ebd45159915fab202e91a007484420f3968697974413fc55d1142dc76285d30b1b9231ccb71ed1e720faae")

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

BlockchainUtils.MnemonicToAddressAndPrivateKey("test test test test test test test test test test test junk")

# BlockchainUtils.CrackSelector("transferFrom", ["address", "address", "uint256"],["address","bytes32"])
