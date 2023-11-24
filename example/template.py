import os
from dotenv import load_dotenv
from Poseidon.Blockchain import *

load_dotenv()
RPCUrl = os.getenv("RPC_URL")
PrivateKey = os.getenv("PRIVATE_KEY")

chain = Chain(RPCUrl)

account = Account(chain, PrivateKey)

account.Transfer("0x0000000000000000000000000000000000000000", 1)

BlockchainUtils.SwitchSolidityVersion("0.8.23")

abi, bytecode = BlockchainUtils.Compile("Test.sol", "Test")

abi = BlockchainUtils.ImportABI("TestABI.json")

contract: Contract = account.DeployContract(abi, bytecode, 0, BlockchainUtils.GweiToWei(10.1), "test params").Contract

contract.CallFunction("writeTest", "test1")

contract.CallFunctionWithParameters(0, BlockchainUtils.GweiToWei(10.1), 100000, "writeTest", "test2")

contract.ReadOnlyCallFunction("readTest")
