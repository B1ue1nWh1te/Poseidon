# type: ignore
from poseidon.evm import Chain, Account, Contract, Utils

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

# rpc_url = "https://ethereum-sepolia.blockpi.network/v1/rpc/public"
rpc_url = "https://arbitrum-sepolia.blockpi.network/v1/rpc/public"
# rpc_url = "https://optimism-sepolia.blockpi.network/v1/rpc/public"
# rpc_url = "https://bsc-testnet.blockpi.network/v1/rpc/public"
# rpc_url = "https://polygon-amoy.blockpi.network/v1/rpc/public"

chain = Chain(rpc_url)
chain_information = chain.get_chain_information(show_client_version=True, show_timeslot=True)
block_information = chain.get_block_information("latest")
transaction_receipt = chain.get_transaction_receipt_by_block_id_and_index(block_information.block_number, 0)
zero_address_balance = chain.get_balance(ZERO_ADDRESS)

address, private_key = Utils.generate_new_account()
input(f"Waiting for sending some testETH to [{address}] ...")
account = Account(chain, private_key)
signature_data_1 = account.sign_message_string("test")
signed_message_data_1 = Utils.recover_message_string("test", signature_data_1.signature_data.signature)
signature_data_2 = account.sign_message_hash(signature_data_1.message_hash)
signed_message_data_2 = Utils.recover_message_hash(signature_data_2.message_hash, signature_data_2.signature_data.signature)

domain_data = {
    "name": "Test",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
}
message_types = {
    "Person": [
        {"name": "name", "type": "string"},
        {"name": "wallet", "type": "address"},
    ],
}
message_data = {
    "name": "test",
    "wallet": account.address
}
signature_data_3 = account.sign_typed_message(domain_data, message_types, message_data)
signed_message_data_3 = Utils.recover_typed_message(domain_data, message_types, message_data, signature_data_3.signature_data.signature)

converted_signature_data_1 = Utils.convert_equivalent_signature(signature_data_1.signature_data.signature)
converted_signed_message_data_1 = Utils.recover_message_string("test", converted_signature_data_1.signature)
print(signed_message_data_1.signer == converted_signed_message_data_1.signer)

account.set_need_confirm_before_send_transaction(need_confirm=True)
transaction_receipt_1 = account.send_transaction(to=ZERO_ADDRESS, data="0xdeadbeef", value=1)
transaction_receipt_2 = account.send_transaction_by_eip1559(to=ZERO_ADDRESS, data="0xdeadbeef", value=1)

Utils.set_solidity_version("0.8.28")
abi, bytecode = Utils.compile_solidity_contract("./Test.sol", "Test")
abi = Utils.import_contract_abi("./TestABI.json")
transaction_receipt_3 = account.deploy_contract(abi, bytecode, 0, None, "test0")
contract: Contract = transaction_receipt_3.contract
contract_code = chain.get_code(contract.address)
contract_storage_0 = chain.get_storage(contract.address, 0)
contract_storage_0_2 = chain.dump_storage(contract.address, 0, 3)

readSlot0_result_1 = contract.read_only_call_function("readSlot0")
calldata_1 = contract.call_function("writeSlot0", "test1").input_data
function, params = contract.decode_function_calldata(calldata_1.hex())
transaction_receipt_4 = contract.call_function_with_parameters(0, chain.eth.gas_price, 100000, "writeSlot0", "test2")
readSlot0_result_2 = contract.read_only_call_function("readSlot0")
calldata_2 = contract.encode_function_calldata("writeSlot0", "test3")
transaction_receipt_5 = account.send_transaction(to=contract.address, data=calldata_2, value=0)
readSlot0_result_3 = contract.read_only_call_function("readSlot0")
create_case_address = Utils.calculate_create_case_contract_address(account.address, 0)
create2_case_address = Utils.calculate_create2_case_contract_address(contract.address, "42", bytecode.hex())
address_from_mnemonic, private_key_from_mnemonic = Utils.generate_account_from_mnemonic("test test test test test test test test test test test junk")

assembly = """
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
bytecode_from_assembly = Utils.assembly_to_bytecode_legacy(assembly)
assembly_from_bytecode = Utils.bytecode_to_assembly_legacy(bytecode_from_assembly.hex())
