from Poseidon_Blockchain import *

Utils.SwitchSolidityVersion("0.8.0")

newAccount = Utils.CreateNewAccount()
print(newAccount)

abi, byteCode = Utils.CompileSolidityToABIAndBytecode("test.sol", "Test")
print(f"{abi}\n{byteCode}")

chain = Chain("https://ropsten.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161")
balance = chain.GetBalance(newAccount[0])
print(balance)
input("此处暂停以向测试账户转一些测试ETH作为后续gas费 完成后回车即可")

account = Account(chain, newAccount[1])
temp = account.SignMessage("test")
print(temp)
signer = Utils.RecoverMessage("test", temp[2])
print(signer)
signer = Utils.RecoverMessageByHash(temp[1], temp[2])
print(signer)

temp = account.SendTransaction("0x000000000000000000000000000000000000dEaD", "0x", 1, 21000)
print(temp)
print(chain.GetTransactionByHash(temp[0]))
print(chain.GetTransactionByBlockIdAndIndex("latest", 0))

temp = account.SendTransaction("0x000000000000000000000000000000000000dEaD", "0x", 1, 1)
print(temp)
temp = account.SendTransactionByEIP1559("0x000000000000000000000000000000000000dEaD", "0x", 1, 21000)
print(temp)
temp = account.SendTransactionByEIP1559("0x000000000000000000000000000000000000dEaD", "0x", 1, 1)
print(temp)

temp = account.DeployContract(abi, byteCode, 0, "test", 0x42)
print(temp)
print(chain.GetCode(temp[0]))
print(chain.GetStorage(temp[0], 0))
print(chain.DumpStorage(temp[0], 2))

temp = account.DeployContractByEIP1559(abi, byteCode, 0, "test", 0x42)
print(temp)
contract = temp[1]
print(contract.CallFunction("change_s", "test2"))
print(contract.CallFunction("change_i", 43))
print(chain.DumpStorage(temp[0], 2))
print(contract.CallFunctionByEIP1559("change_s", "test3"))
print(contract.CallFunctionByEIP1559("change_i", 44))
print(chain.DumpStorage(temp[0], 2))
print(contract.ReadOnlyCallFunction("i"))
print(contract.EncodeABI("change_s", "test5"))
