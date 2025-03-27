"""
本模块主要基于 web3.py 对常用的 EVM 链上交互操作进行了模块化抽象与简洁式封装。
"""

from eth_account.datastructures import SignedMessage, SignedTransaction
from eth_account.signers.local import LocalAccount
from eth_typing import BlockNumber, ChecksumAddress
from eth_typing.encoding import HexStr
from hexbytes import HexBytes
from typing import Any, List, Optional, Sequence, Tuple, Union
from web3.types import BlockIdentifier, LogReceipt, Nonce, Timestamp, TxData, Wei, _Hash32

import os
from dataclasses import dataclass
from importlib.metadata import version
from json import dump, dumps, load
from loguru import logger
from time import time
from traceback import format_exc

from ellipticcurve.curve import secp256k1
from eth_account import Account as EthAccount
from eth_account.messages import encode_defunct, encode_typed_data, _hash_eip191_message
from pyevmasm import assemble_hex, disassemble_hex
from solcx import compile_source, get_solc_version, install_solc, set_solc_version
from web3 import HTTPProvider, utils, Web3
from web3.middleware.geth_poa import geth_poa_middleware

LOG_DIVIDER_LINE = "-" * 80

_log_path = os.path.join("logs", "poseidon_evm_{time}.log")
_version = version("poseidon-python")
logger.add(_log_path)
logger.success(f"\n[Poseidon][EVM][v{_version}]\n{LOG_DIVIDER_LINE}")


@dataclass
class ChainInformationData:
    chain_id: int
    block_number: BlockNumber
    gas_price: Wei
    timeslot: Optional[int]
    client_version: Optional[str]


@dataclass
class BlockInformationData:
    block_hash: HexBytes
    block_number: BlockNumber
    timestamp: Timestamp
    miner: ChecksumAddress
    gas_used: int
    gas_limit: int
    transactions: Union[Sequence[HexBytes], Sequence[TxData]]


@dataclass
class TransactionReceiptData:
    transaction_hash: HexBytes
    block_number: BlockNumber
    transaction_index: int
    transaction_status: int
    transaction_type: int
    action: str
    sender: ChecksumAddress
    to: ChecksumAddress
    nonce: Nonce
    value: Wei
    gas_price: Optional[Wei]
    max_fee_per_gas: Optional[Wei]
    max_priority_fee_per_gas: Optional[Wei]
    effective_gas_price: Optional[Wei]
    gas_used: int
    gas_limit: int
    contract_address: Optional[ChecksumAddress]
    contract: Optional[Any]
    logs: Optional[List[LogReceipt]]
    input_data: HexBytes
    r: HexBytes
    s: HexBytes
    v: HexBytes


@dataclass
class SignatureData:
    signature: HexBytes
    r: HexBytes
    s: HexBytes
    v: HexBytes


@dataclass
class SignedMessageData:
    message_hash: HexBytes
    message: Optional[str]
    signer: ChecksumAddress
    signature_data: SignatureData


class Chain:
    """
    Chain 是 EVM 链实例，后续的所有链上交互操作都将发往该链处理。
    """

    def __init__(self, rpc_url: str, request_params: Optional[dict] = None) -> None:
        """
        实例初始化。根据给定的节点 RPC 地址以 HTTP/HTTPS 方式进行连接，可通过代理访问。

        参数：
            rpc_url (str): 节点 RPC 地址
            request_params (Optional[dict] = None): 连接时使用的 request 参数
            例如当需要使用代理进行访问时，则传入 request_params = {"proxies": {"http": "http://localhost:<ProxyPort>","https": "http://localhost:<ProxyPort>"}}

        成员变量：
            chain_id (int): 链 ID
            provider (web3.HTTPProvider): web3.py 原生的 HTTPProvider 实例
            eth (web3.HTTPProvider.eth): HTTPProvider 实例中的 eth 模块
        """

        start_time = time()
        request_params_print = f"[request_params]{request_params}" if request_params else ""
        self.provider = Web3(HTTPProvider(rpc_url, request_kwargs=request_params))
        if self.provider.is_connected():
            self.provider.middleware_onion.inject(geth_poa_middleware, layer=0)
            self.eth = self.provider.eth
            self.chain_id = self.eth.chain_id
            finish_time = time()
            delay = round((finish_time - start_time) * 1000)
            logger.success(f"\n[Chain][__init__]Connected to [{rpc_url}] [{delay}ms]{request_params_print}\n{LOG_DIVIDER_LINE}")
            self.get_chain_information(show_timeslot=False, show_client_version=False)
        else:
            logger.error(f"\n[Chain][__init__]Failed to connect to [{rpc_url}]\n{request_params_print}\n{LOG_DIVIDER_LINE}")
            raise Exception("Failed to connect to chain.")

    def get_chain_information(self, show_timeslot: bool = True, show_client_version: bool = True) -> ChainInformationData:
        """
        获取 EVM 链基本信息。

        参数：
            show_timeslot (bool = True): 是否显示 timeslot 
            show_client_version (bool = True): 是否显示 client_version 

        返回值：
            chain_information (poseidon.evm.ChainInformationData): EVM 链基本信息
            {"chain_id"|"block_number"|"gas_price"|("timeslot")|("client_version")}
        """

        chain_id = self.chain_id
        block_number = self.eth.block_number
        gas_price = self.eth.gas_price

        timeslot_print = ""
        if show_timeslot:
            timeslot = round(int(self.eth.get_block(block_number).get("timestamp", 0) - self.eth.get_block(block_number - 100).get("timestamp", 0))/100, 2)
            timeslot_print = f"\n[timeslot]{timeslot}s"

        client_version_print = ""
        if show_client_version:
            client_version = self.provider.client_version
            client_version_print = f"\n[client_version]{client_version}"

        chain_information = ChainInformationData(**{
            "chain_id": chain_id,
            "block_number": block_number,
            "gas_price": gas_price,
            "timeslot": timeslot if show_timeslot else None,
            "client_version": client_version if show_client_version else None
        })
        logger.success(
            f"\n[Chain][get_chain_information]\n[chain_id]{chain_id}\n[block_number]{block_number}\n[gas_price]{Web3.from_wei(gas_price, 'gwei')} Gwei{timeslot_print}{client_version_print}\n{LOG_DIVIDER_LINE}"
        )
        return chain_information

    def get_block_information(self, block_id: BlockIdentifier) -> Optional[BlockInformationData]:
        """
        根据区块 ID 获取该区块基本信息。

        参数：
            block_id (web3.types.BlockIdentifier): 区块 ID (可为具体区块号、区块哈希或 'latest','earliest','pending' 等标识符)

        返回值：
            block_information (Optional[BlockInformationData]): 区块基本信息
            {"block_hash"|"block_number"|"timestamp"|"miner"|"gas_used"|"gas_limit"|"transactions"}
        """

        try:
            info = self.eth.get_block(block_id, True)
            block_hash = HexBytes(info.get("hash", ""))
            block_number = info.get("number")
            timestamp = info.get("timestamp")
            miner = info.get("miner")
            gas_used = info.get("gasUsed")
            gas_limit = info.get("gasLimit")
            transactions = info.get("transactions")

            block_information = BlockInformationData(**{
                "block_hash": block_hash,
                "block_number": block_number,
                "timestamp": timestamp,
                "miner": miner,
                "gas_used": gas_used,
                "gas_limit": gas_limit,
                "transactions": transactions
            })
            logger.success(
                f"\n[Chain][get_block_information]\n[block_hash]{block_hash.hex()}\n[block_number]{block_number}\n[timestamp]{timestamp}\n[miner]{miner}\n[gas_used]{gas_used}\n[gas_limit]{gas_limit}\n[transactions]{transactions}\n{LOG_DIVIDER_LINE}"
            )
            return block_information
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Chain][get_block_information]Failed\n[block_id]{block_id}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def get_transaction_receipt_by_hash(self, transaction_hash: _Hash32) -> Optional[TransactionReceiptData]:
        """
        根据交易哈希获取该交易的回执信息。

        参数：
            transaction_hash (web3.types._Hash32): 交易哈希

        返回值：
            transaction_receipt (Optional[TransactionReceiptData]): 交易回执信息
            {"transaction_hash"|"block_number"|"transaction_index"|"transaction_status"|"transaction_type"|"action"|"sender"|"to"|"nonce"|"value"|"gas_used"|"gas_limit"|<"gas_price"|("max_fee_per_gas"&"max_priority_fee_per_gas"&"effective_gas_price")>|("contract_address")|"logs"|"input_data"|"r"|"s"|"v"}
        """

        try:
            info = self.eth.wait_for_transaction_receipt(transaction_hash, timeout=60, poll_latency=0.2)
            block_number = info.get("blockNumber")
            transaction_index = info.get("transactionIndex")
            transaction_status = info.get("status")
            transaction_type = info.get("type")
            sender = info.get("from")
            to = info.get("to")
            effective_gas_price = info.get("effectiveGasPrice")
            gas_used = info.get("gasUsed")
            contract_address = info.get("contractAddress")
            logs = info.get("logs")
            action = "Deploy Contract" if not to else "Interactive Contract" if to and len(self.eth.get_code(to).hex()) > 2 else "Native Transfer"

            info = self.eth.get_transaction(transaction_hash)
            _transaction_hash = HexBytes(info.get("hash", ""))
            nonce = info.get("nonce")
            value = info.get("value")
            gas_limit = info.get("gas")
            gas_price = Wei(info.get("gasPrice", 0))
            max_fee_per_gas = Wei(info.get("maxFeePerGas", 0))
            max_priority_fee_per_gas = Wei(info.get("maxPriorityFeePerGas", 0))
            input_data = HexBytes(info.get("input", ""))
            r = HexBytes(info.get("r", ""))
            s = HexBytes(info.get("s", ""))
            v = HexBytes(hex(info.get("v", 0)))

            transaction_receipt = TransactionReceiptData(**{
                "transaction_hash": _transaction_hash,
                "block_number": block_number,
                "transaction_index": transaction_index,
                "transaction_status": transaction_status,
                "transaction_type": transaction_type,
                "action": action,
                "sender": sender,
                "to": to,
                "nonce": nonce,
                "value": value,
                "gas_used": gas_used,
                "gas_limit": gas_limit,
                "contract_address": contract_address,
                "contract": None,
                "gas_price": gas_price,
                "max_fee_per_gas": max_fee_per_gas,
                "max_priority_fee_per_gas": max_priority_fee_per_gas,
                "effective_gas_price": effective_gas_price,
                "logs": logs,
                "input_data": input_data,
                "r": r,
                "s": s,
                "v": v
            })

            _transaction_status = 'Success' if transaction_status else 'Failed'
            _transaction_type = "EIP-155" if transaction_type == 0 else "EIP-2930" if transaction_type == 1 else "EIP-1559" if transaction_type == 2 else "EIP-4844" if transaction_type == 3 else "EIP-7702" if transaction_type == 4 else "Unknown"
            gas_price_print = f"\n[max_fee_per_gas]{Web3.from_wei(max_fee_per_gas, 'gwei')} Gwei\n[max_priority_fee_per_gas]{Web3.from_wei(max_priority_fee_per_gas, 'gwei')} Gwei\n[effective_gas_price]{Web3.from_wei(effective_gas_price, 'gwei')} Gwei" if _transaction_type == "EIP-1559" or _transaction_type == "EIP-4844" or _transaction_type == "EIP-7702" else f"\n[gas_price]{Web3.from_wei(gas_price, 'gwei')} Gwei"
            contract_address_print = f"\n[contract_address]{contract_address}" if contract_address else ""

            general_print = f"\n[Chain][get_transaction_receipt_by_hash]\n[transaction_hash]{_transaction_hash.hex()}\n[block_number]{block_number}\n[transaction_index]{transaction_index}\n[status]{_transaction_status}\n[transaction_type]{_transaction_type}\n[action]{action}\n[sender]{sender}\n[to]{to}\n[nonce]{nonce} [value]{value}\n[gas_used]{gas_used} [gas_limit]{gas_limit}{gas_price_print}{contract_address_print}\n[logs]{logs}\n[input_data]{input_data.hex()}\n[r]{r.hex()}\n[s]{s.hex()}\n[v]{v.hex()}\n{LOG_DIVIDER_LINE}"

            if transaction_status:
                logger.success(general_print)
            else:
                logger.error(general_print)

            return transaction_receipt
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Chain][get_transaction_receipt_by_hash]Failed\n[transaction_hash]{transaction_hash}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def get_transaction_receipt_by_block_id_and_index(self, block_id: BlockIdentifier, transaction_index: int) -> Optional[TransactionReceiptData]:
        """
        根据区块 ID 和索引来获取该交易的回执信息。

        参数：
            block_id (web3.types.BlockIdentifier): 区块 ID (可为具体区块号、区块哈希或 'latest','earliest','pending' 等标识符)
            transaction_index (int): 索引

        返回值：
            transaction_receipt (Optional[TransactionReceiptData]): 交易回执信息
            {"transaction_hash"|"block_number"|"transaction_index"|"transaction_status"|"transaction_type"|"action"|"sender"|"to"|"nonce"|"value"|"gas_used"|"gas_limit"|<"gas_price"|("max_fee_per_gas"&"max_priority_fee_per_gas"&"effective_gas_price")>|("contract_address")|"logs"|"input_data"|"r"|"s"|"v"}
        """

        try:
            info = self.eth.get_transaction_by_block(block_id, transaction_index)
            transaction_hash = HexBytes(info.get("hash", ""))
            block_number = info.get("blockNumber")
            _transaction_index = info.get("transactionIndex")
            sender = info.get("from")
            to = info.get("to")
            nonce = info.get("nonce")
            value = info.get("value")
            gas_limit = info.get("gas")
            gas_price = Wei(info.get("gasPrice", 0))
            max_fee_per_gas = Wei(info.get("maxFeePerGas", 0))
            max_priority_fee_per_gas = Wei(info.get("maxPriorityFeePerGas", 0))
            input_data = HexBytes(info.get("input", ""))
            r = HexBytes(info.get("r", ""))
            s = HexBytes(info.get("s", ""))
            v = HexBytes(hex(info.get("v", 0)))
            action = "Deploy Contract" if not to else "Interactive Contract" if to and len(self.eth.get_code(to).hex()) > 2 else "Native Transfer"

            info = self.eth.get_transaction_receipt(transaction_hash)
            transaction_status = info.get("status")
            transaction_type = info.get("type")
            gas_used = info.get("gasUsed")
            effective_gas_price = info.get("effectiveGasPrice")
            contract_address = info.get("contractAddress")
            logs = info.get("logs")

            transaction_information = TransactionReceiptData(**{
                "transaction_hash": transaction_hash,
                "block_number": block_number,
                "transaction_index": _transaction_index,
                "transaction_status": transaction_status,
                "transaction_type": transaction_type,
                "action": action,
                "sender": sender,
                "to": to,
                "nonce": nonce,
                "value": value,
                "gas_used": gas_used,
                "gas_limit": gas_limit,
                "contract_address": contract_address,
                "contract": None,
                "gas_price": gas_price,
                "max_fee_per_gas": max_fee_per_gas,
                "max_priority_fee_per_gas": max_priority_fee_per_gas,
                "effective_gas_price": effective_gas_price,
                "logs": logs,
                "input_data": input_data,
                "r": r,
                "s": s,
                "v": v
            })

            _transaction_status = 'Success' if transaction_status else 'Failed'
            _transaction_type = "EIP-155" if transaction_type == 0 else "EIP-2930" if transaction_type == 1 else "EIP-1559" if transaction_type == 2 else "EIP-4844" if transaction_type == 3 else "Unknown"
            gas_price_print = f"\n[max_fee_per_gas]{Web3.from_wei(max_fee_per_gas, 'gwei')} Gwei\n[max_priority_fee_per_gas]{Web3.from_wei(max_priority_fee_per_gas, 'gwei')} Gwei\n[effective_gas_price]{Web3.from_wei(effective_gas_price, 'gwei')} Gwei" if _transaction_type == "EIP-1559" or _transaction_type == "EIP-4844" else f"\n[gas_price]{Web3.from_wei(gas_price, 'gwei')} Gwei"
            contract_address_print = f"\n[contract_address]{contract_address}" if contract_address else ""

            general_print = f"\n[Chain][get_transaction_receipt_by_block_id_and_index]\n[transaction_hash]{transaction_hash.hex()}\n[block_number]{block_number}\n[transaction_index]{transaction_index}\n[status]{_transaction_status}\n[transaction_type]{_transaction_type}\n[action]{action}\n[sender]{sender}\n[to]{to}\n[nonce]{nonce} [value]{value}\n[gas_used]{gas_used} [gas_limit]{gas_limit}{gas_price_print}{contract_address_print}\n[logs]{logs}\n[input_data]{input_data.hex()}\n[r]{r.hex()}\n[s]{s.hex()}\n[v]{v.hex()}\n{LOG_DIVIDER_LINE}"

            if transaction_status:
                logger.success(general_print)
            else:
                logger.error(general_print)

            return transaction_information
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Chain][get_transaction_receipt_by_block_id_and_index]Failed\n[block_id]{block_id}\n[transaction_index]{transaction_index}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def get_balance(self, address: ChecksumAddress) -> Optional[Wei]:
        """
        根据账户地址获取其原生代币余额。

        参数：
            address (eth_typing.ChecksumAddress): 账户地址

        返回值：
            balance (Optional[Wei]): 账户原生代币余额
        """

        try:
            _address = Web3.to_checksum_address(address)
            balance = self.eth.get_balance(_address, block_identifier="latest")
            logger.success(
                f"\n[Chain][get_balance]\n[address]{_address}\n[balance][{balance} Wei]<=>[{Web3.from_wei(balance,'ether')} Ether]\n{LOG_DIVIDER_LINE}"
            )
            return balance
        except Exception:
            exception_information = format_exc()
            logger.error(f"\n[Chain][get_balance]Failed\n[address]{address}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}")
            return None

    def get_code(self, address: ChecksumAddress) -> Optional[HexBytes]:
        """
        根据合约地址获取其字节码。

        参数：
            address (eth_typing.ChecksumAddress): 合约地址

        返回值：
            bytecode (Optional[HexBytes]): 合约字节码
        """

        try:
            _address = Web3.to_checksum_address(address)
            bytecode = self.eth.get_code(_address, block_identifier="latest")
            logger.success(f"\n[Chain][get_code]\n[address]{_address}\n[bytecode]{bytecode.hex()}\n{LOG_DIVIDER_LINE}")
            return bytecode
        except Exception:
            exception_information = format_exc()
            logger.error(f"\n[Chain][get_code]Failed\n[address]{address}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}")
            return None

    def get_storage(self, address: ChecksumAddress, slot_index: int) -> Optional[HexBytes]:
        """
        根据合约地址和存储插槽索引获取存储值。

        参数：
            address (eth_typing.ChecksumAddress): 合约地址
            slot_index (int): 存储插槽索引

        返回值：
            storage_data (Optional[HexBytes]): 存储值
        """

        try:
            _address = Web3.to_checksum_address(address)
            storage_data = self.eth.get_storage_at(_address, slot_index, block_identifier="latest")
            logger.success(
                f"\n[Chain][get_storage]\n[address]{_address}\n[slot_index]{slot_index}\n[storage_data]{storage_data.hex()}\n{LOG_DIVIDER_LINE}"
            )
            return storage_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Chain][get_storage]Failed\n[address]{address}\n[slot_index]{slot_index}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def dump_storage(self, address: ChecksumAddress, start_slot_index: int, end_slot_index: int) -> Optional[List[HexBytes]]:
        """
        根据合约地址和起止插槽索引，批量获取存储值。

        参数：
            address (eth_typing.ChecksumAddress): 合约地址
            start_slot_index (int): 起始插槽索引
            end_slot_index (int): 终止插槽索引

        返回值：
            storage_data_list (Optional[List[HexBytes]]): 存储值列表
        """

        try:
            _address = Web3.to_checksum_address(address)
            latest_block_number = self.eth.block_number
            storage_data_list = [self.eth.get_storage_at(_address, i, block_identifier=latest_block_number) for i in range(start_slot_index, end_slot_index)]
            storage_data_list_print = '\n'.join([f"[slot {start_slot_index + i}]{storage_data_list[i].hex()}" for i in range(len(storage_data_list))])
            logger.success(f"\n[Chain][dump_storage]\n[address]{_address}\n{storage_data_list_print}\n{LOG_DIVIDER_LINE}")
            return storage_data_list
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Chain][dump_storage]Failed\n[address]{address}\n[start_slot_index]{start_slot_index}\n[end_slot_index]{end_slot_index}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None


class Account:
    """
    Account 是账户实例，后续的交易将由该账户签署并发送至链上。
    """

    def __init__(self, chain: Chain, private_key: HexBytes) -> None:
        """
        实例初始化。通过私钥导入账户并与 Chain 实例绑定。

        参数：
            chain (poseidon.evm.Chain): EVM 链实例
            private_key (hexbytes.HexBytes): 账户私钥

        成员变量：
            eth_account (eth_account.LocalAccount): eth_account 的 LocalAccount 实例
            address (eth_typing.ChecksumAddress): 账户地址
            private_key (hexbytes.HexBytes): 账户私钥
        """

        try:
            self.eth_account: LocalAccount = EthAccount.from_key(private_key)
            self.address = ChecksumAddress(self.eth_account.address)
            self.private_key = HexBytes(self.eth_account.key)
            self._chain = chain
            self._chain.eth.default_account = self.address
            logger.success(f"\n[Account][__init__]Successfully import account [{self.address}]\n{LOG_DIVIDER_LINE}")
            self.set_need_confirm_before_send_transaction(need_confirm=False)
            self.get_self_balance()
        except Exception:
            exception_information = format_exc()
            logger.error(f"\n[Account][__init__]Failed to import account\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}")
            raise Exception("Failed to import account.")

    def set_need_confirm_before_send_transaction(self, need_confirm: bool = True) -> None:
        """
        设置在通过该账户发送每一笔交易之前是否需要控制台回车确认。开启后会在每笔交易即将发送前暂停流程，在控制台询问是否发送该笔交易。

        参数：
            need_confirm (bool): 是否需要控制台回车确认
        """

        self._need_confirm = need_confirm
        if self._need_confirm:
            logger.success(f"\n[Account][set_need_confirm_before_send_transaction][True]\n{LOG_DIVIDER_LINE}")
        else:
            logger.warning(f"\n[Account][set_need_confirm_before_send_transaction][False]\n{LOG_DIVIDER_LINE}")

    def _confirm_before_send_transaction(self) -> None:
        if self._need_confirm:
            logger.warning("\n[Account][_confirm_before_send_transaction]\nDo you confirm sending this transaction?")
            command = input("Command Input (yes/1/[Enter] or no/0):")
            if command == "no" or command == "0" or (len(command) > 0 and command != "yes" and command != "1"):
                raise Exception("Cancel sending transaction.")

    def get_self_balance(self) -> Optional[Wei]:
        """
        获取当前账户的原生代币余额。

        返回值：
            balance (Optional[Wei]): 当前账户的原生代币余额
        """

        balance = self._chain.get_balance(self.address)
        if balance == 0:
            logger.warning(f"\n[Account][get_self_balance]\n[warning]This account's balance is zero\n{LOG_DIVIDER_LINE}")
        return balance

    def send_transaction(self, to: Optional[ChecksumAddress] = None, data: HexBytes = HexBytes("0x"), value: Wei = Wei(0), gas_price: Optional[Wei] = None, gas_limit: int = 500000) -> Optional[TransactionReceiptData]:
        """
        发送自定义 EIP-155 交易。

        参数：
            to (Optional[ChecksumAddress] = None): 接收者地址
            data (hexbytes.HexBytes = HexBytes("0x")): 交易数据
            value (web3.types.Wei = Wei(0)): 发送的原生代币数量
            gas_price (Optional[Wei] = None): Gas 价格
            gas_limit (int = 500000): Gas 最大使用量

        返回值：
            transaction_receipt (Optional[TransactionReceiptData]): 交易回执信息
            {"transaction_hash"|"block_number"|"transaction_index"|"transaction_status"|"transaction_type"|"action"|"sender"|"to"|"nonce"|"value"|"gas_used"|"gas_limit"|<"gas_price"|("max_fee_per_gas"&"max_priority_fee_per_gas"&"effective_gas_price")>|("contract_address")|"logs"|"input_data"|"r"|"s"|"v"}
        """

        try:
            sender = self.address
            txn = {
                "chainId": self._chain.chain_id,
                "from": sender,
                "to": Web3.to_checksum_address(to) if to else None,
                "value": value,
                "gas": gas_limit,
                "gasPrice": gas_price if gas_price else self._chain.eth.gas_price,
                "nonce": self._chain.eth.get_transaction_count(sender, block_identifier="latest"),
                "data": data,
            }
            signed_txn: SignedTransaction = self.eth_account.sign_transaction(txn)
            txn["gasPrice"] = f'{Web3.from_wei(txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][send_transaction]\n[txn]{dumps(txn, indent=2)}\n{LOG_DIVIDER_LINE}")

            self._confirm_before_send_transaction()
            transaction_hash = self._chain.eth.send_raw_transaction(signed_txn.rawTransaction)
            logger.info(f"\n[Account][send_transaction][pending...]\n[transaction_hash]{transaction_hash.hex()}\n{LOG_DIVIDER_LINE}")
            transaction_receipt = self._chain.get_transaction_receipt_by_hash(transaction_hash)
            return transaction_receipt
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Account][send_transaction]Failed\n[to]{to}\n[value]{value}\n[data]{data.hex()}\n[gas_price]{gas_price}\n[gas_limit]{gas_limit}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def send_transaction_by_eip1559(self, to: Optional[ChecksumAddress] = None, data: HexBytes = HexBytes("0x"), value: Wei = Wei(0), base_fee: Optional[Wei] = None, max_priority_fee: Optional[Wei] = None, gas_limit: int = 500000) -> Optional[TransactionReceiptData]:
        """
        发送自定义 EIP-1559 交易。

        参数：
            to (Optional[ChecksumAddress] = None): 接收者地址
            data (hexbytes.HexBytes = HexBytes("0x")): 交易数据
            value (web3.types.Wei = Wei(0)): 发送的原生代币数量
            base_fee (Optional[Wei] = None): 基础费用
            max_priority_fee (Optional[Wei] = None): 最高优先费用
            gas_limit (int = 500000): Gas 最大使用量

        返回值：
            transaction_receipt (Optional[TransactionReceiptData]): 交易回执信息
            {"transaction_hash"|"block_number"|"transaction_index"|"transaction_status"|"transaction_type"|"action"|"sender"|"to"|"nonce"|"value"|"gas_used"|"gas_limit"|<"gas_price"|("max_fee_per_gas"&"max_priority_fee_per_gas"&"effective_gas_price")>|("contract_address")|"logs"|"input_data"|"r"|"s"|"v"}
        """

        try:
            sender = self.address
            base_fee = base_fee if base_fee else self._chain.eth.gas_price
            max_priority_fee = max_priority_fee if max_priority_fee else self._chain.eth.max_priority_fee
            txn = {
                "chainId": self._chain.chain_id,
                "from": sender,
                "to": Web3.to_checksum_address(to) if to else None,
                "value": value,
                "gas": gas_limit,
                "maxFeePerGas": base_fee + max_priority_fee,
                "maxPriorityFeePerGas": max_priority_fee,
                "nonce": self._chain.eth.get_transaction_count(sender, block_identifier="latest"),
                "data": data,
            }
            signed_txn: SignedTransaction = self.eth_account.sign_transaction(txn)
            txn["maxFeePerGas"] = f'{Web3.from_wei(txn["maxFeePerGas"],"gwei")} Gwei'
            txn["maxPriorityFeePerGas"] = f'{Web3.from_wei(txn["maxPriorityFeePerGas"],"gwei")} Gwei'
            logger.info(f"\n[Account][send_transaction_by_eip1559]\n[txn]{dumps(txn, indent=2)}\n{LOG_DIVIDER_LINE}")

            self._confirm_before_send_transaction()
            transaction_hash = self._chain.eth.send_raw_transaction(signed_txn.rawTransaction)
            logger.info(f"\n[Account][send_transaction_by_eip1559][pending...]\n[transaction_hash]{transaction_hash.hex()}\n{LOG_DIVIDER_LINE}")
            transaction_receipt = self._chain.get_transaction_receipt_by_hash(transaction_hash)
            return transaction_receipt
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Account][send_transaction_by_eip1559]Failed\n[to]{to}\n[value]{value}\n[data]{data.hex()}\n[base_fee]{base_fee}\n[max_priority_fee]{max_priority_fee}\n[gas_limit]{gas_limit}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def deploy_contract(self, abi: dict, bytecode: HexBytes, value: Wei = Wei(0), gas_price: Optional[Wei] = None, *args: Optional[Any]) -> Optional[TransactionReceiptData]:
        """
        部署合约。

        参数：
            abi (dict): 合约 ABI
            bytecode (hexbytes.HexBytes): 合约字节码
            value (web3.types.Wei = Wei(0)): 发送给合约的原生代币数量
            gas_price (Optional[Wei] = None): Gas 价格
            *args (Optional[Any]): 传给合约构造函数的参数

        返回值：
            transaction_receipt (Optional[TransactionReceiptData]): 交易回执信息
            当合约部署成功时，返回值中会额外添加"contract"字段，该变量是 poseidon.evm.Contract 实例，若失败则为 None。
            {"transaction_hash"|"block_number"|"transaction_index"|"transaction_status"|"transaction_type"|"action"|"sender"|"to"|"nonce"|"value"|"gas_used"|"gas_limit"|<"gas_price"|("max_fee_per_gas"&"max_priority_fee_per_gas"&"effective_gas_price")>|("contract_address"&"contract")|"logs"|"input_data"|"r"|"s"|"v"|"contract"}
        """

        try:
            deploying_contract = self._chain.eth.contract(abi=abi, bytecode=bytecode)
            transaction_data = deploying_contract.constructor(*args).build_transaction({"value": value, "gasPrice": gas_price if gas_price else self._chain.eth.gas_price})
            txn = {
                "chainId": self._chain.chain_id,
                "from": self.address,
                "value": transaction_data["value"],
                "gas": transaction_data["gas"],
                "gasPrice": transaction_data["gasPrice"],
                "nonce": self._chain.eth.get_transaction_count(self.address),
                "data": transaction_data["data"]
            }
            signed_txn: SignedTransaction = self.eth_account.sign_transaction(txn)
            txn["gasPrice"] = f'{Web3.from_wei(txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][deploy_contract]\n[txn]{dumps(txn, indent=2)}\n{LOG_DIVIDER_LINE}")

            self._confirm_before_send_transaction()
            transaction_hash = self._chain.eth.send_raw_transaction(signed_txn.rawTransaction)
            logger.info(f"\n[Account][deploy_contract][pending...]\n[transaction_hash]{transaction_hash.hex()}\n{LOG_DIVIDER_LINE}")
            transaction_receipt = self._chain.get_transaction_receipt_by_hash(transaction_hash)

            if transaction_receipt:
                if transaction_receipt.transaction_status and transaction_receipt.contract_address:
                    deployed_contract = Contract(self, transaction_receipt.contract_address, abi)
                    transaction_receipt.contract = deployed_contract
                else:
                    transaction_receipt.contract = None

            return transaction_receipt
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Account][deploy_contract]Failed\n[value]{value}\n[gas_price]{gas_price}\n[abi]{abi}\n[bytecode]{bytecode.hex()}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def sign_message_string(self, message: str) -> Optional[SignedMessageData]:
        """
        对消息字符串进行签名。

        参数：
            message (str): 待签名消息字符串

        返回值：
            signed_message_data (Optional[SignedMessageData]): 签名数据
            {"message_hash"|"message"|"signer"|"signature_data"}
        """

        try:
            signer = self.eth_account.address
            signed_message: SignedMessage = self.eth_account.sign_message(encode_defunct(text=message))
            message_hash = signed_message.messageHash
            signature = signed_message.signature
            r = HexBytes(hex(signed_message.r))
            s = HexBytes(hex(signed_message.s))
            v = HexBytes(hex(signed_message.v))
            signed_message_data = SignedMessageData(**{
                "message_hash": message_hash,
                "message": message,
                "signer": signer,
                "signature_data": SignatureData(**{
                    "signature": signature,
                    "r": r,
                    "s": s,
                    "v": v
                })
            })
            logger.success(
                f"\n[Account][sign_message_string]\n[message_hash]{message_hash.hex()}\n[message]{message}\n[signer]{signer}\n[signature]{signature.hex()}\n[r]{r.hex()}\n[s]{s.hex()}\n[v]{v.hex()}\n{LOG_DIVIDER_LINE}"
            )
            return signed_message_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Account][sign_message_string]Failed to sign message\n[message]{message}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def sign_message_raw_hash(self, message_raw_hash: HexBytes) -> Optional[SignedMessageData]:
        """
        对消息哈希进行原生签名。

        参数：
            message_raw_hash (hexbytes.HexBytes): 待签名消息哈希

        返回值：
            signed_message_data (Optional[SignedMessageData]): 签名数据
            {"message_hash"|"message"|"signer"|"signature_data"}
        """

        try:
            signer = self.eth_account.address
            signed_message: SignedMessage = self.eth_account.signHash(message_raw_hash)
            _message_raw_hash = signed_message.messageHash
            signature = signed_message.signature
            r = HexBytes(hex(signed_message.r))
            s = HexBytes(hex(signed_message.s))
            v = HexBytes(hex(signed_message.v))
            signed_message_data = SignedMessageData(**{
                "message_hash": _message_raw_hash,
                "message": None,
                "signer": signer,
                "signature_data": SignatureData(**{
                    "signature": signature,
                    "r": r,
                    "s": s,
                    "v": v
                })
            })
            logger.success(
                f"\n[Account][sign_message_raw_hash]\n[message_raw_hash]{_message_raw_hash.hex()}\n[signer]{signer}\n[signature]{signature.hex()}\n[r]{r.hex()}\n[s]{s.hex()}\n[v]{v.hex()}\n{LOG_DIVIDER_LINE}"
            )
            return signed_message_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Account][sign_message_raw_hash]Failed\n[message_raw_hash]{message_raw_hash}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def sign_message_hash(self, message_hash: HexBytes) -> Optional[SignedMessageData]:
        """
        对消息哈希进行 EIP-191 签名。

        参数：
            message_hash (hexbytes.HexBytes): 待签名消息哈希

        返回值：
            signed_message_data (Optional[SignedMessageData]): 签名数据
            {"message_hash"|"message"|"signer"|"signature_data"}
        """

        try:
            signer = self.eth_account.address
            signed_message: SignedMessage = self.eth_account.sign_message(encode_defunct(hexstr=message_hash.hex()))
            _message_hash = signed_message.messageHash
            signature = signed_message.signature
            r = HexBytes(hex(signed_message.r))
            s = HexBytes(hex(signed_message.s))
            v = HexBytes(hex(signed_message.v))
            signed_message_data = SignedMessageData(**{
                "message_hash": _message_hash,
                "message": None,
                "signer": signer,
                "signature_data": SignatureData(**{
                    "signature": signature,
                    "r": r,
                    "s": s,
                    "v": v
                })
            })
            logger.success(
                f"\n[Account][sign_message_hash]\n[message_hash]{_message_hash.hex()}\n[signer]{signer}\n[signature]{signature.hex()}\n[r]{r.hex()}\n[s]{s.hex()}\n[v]{v.hex()}\n{LOG_DIVIDER_LINE}"
            )
            return signed_message_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Account][sign_message_hash]Failed\n[message_hash]{message_hash}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def sign_typed_message(self, domain_data: dict, message_types: dict, message_data: dict) -> Optional[SignedMessageData]:
        """
        对结构化消息数据进行 EIP-712 签名。

        参数：
            domain_data (dict): 域数据
            message_types (dict): 消息类型定义
            message_data (dict): 待签名的消息数据

        返回值：
            signed_message_data (Optional[SignedMessageData]): 签名数据
            {"message_hash"|"message"|"signer"|"signature_data"}
        """

        try:
            signer = self.eth_account.address
            signable_message = encode_typed_data(domain_data, message_types, message_data)
            signed_message: SignedMessage = self.eth_account.sign_message(signable_message)
            message_hash = signed_message.messageHash
            message = f"{domain_data}\n{message_types}\n{message_data}"
            signature = signed_message.signature
            r = HexBytes(hex(signed_message.r))
            s = HexBytes(hex(signed_message.s))
            v = HexBytes(hex(signed_message.v))
            signed_message_data = SignedMessageData(**{
                "message_hash": message_hash,
                "message": message,
                "signer": signer,
                "signature_data": SignatureData(**{
                    "signature": signature,
                    "r": r,
                    "s": s,
                    "v": v
                })
            })
            logger.success(
                f"\n[Account][sign_typed_message]\n[message_hash]{message_hash.hex()}\n[message]\n{message}\n[signer]{signer}\n[signature]{signature.hex()}\n[r]{r.hex()}\n[s]{s.hex()}\n[v]{v.hex()}\n{LOG_DIVIDER_LINE}"
            )
            return signed_message_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Account][sign_typed_message]Failed\n[domain_data]{domain_data}\n[message_data]{message_data}\n[message_types]{message_types}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None


class Contract:
    """
    Contract 是合约实例，后续需要基于该实例调用合约中的函数。
    """

    def __init__(self, account: Account, address: ChecksumAddress, abi: dict) -> None:
        """
        实例初始化。通过合约地址与 ABI 来实例化合约，并与 Account 绑定，后续所有对该合约的调用都会由这一账户发起。

        参数：
            account (poseidon.evm.Account): 账户实例
            address (web3.types.ChecksumAddress): 合约地址
            abi (dict): 合约 ABI

        成员变量：
            address (web3.types.ChecksumAddress): 合约地址
            web3py_contract (web3.HTTPProvider.eth.Contract): web3.py 原生的 Contract 实例
        """

        try:
            self._account = account
            self._eth = account._chain.eth
            self.address = Web3.to_checksum_address(address)
            self.web3py_contract = self._eth.contract(address=self.address, abi=abi)
            logger.success(f"\n[Contract][__init__]Successfully instantiated contract [{self.address}]\n{LOG_DIVIDER_LINE}")
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Contract][__init__]Failed to instantiated contract [{self.address}]\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            raise Exception("Failed to instantiate contract.")

    def call_function(self, function_name: str, *args: Optional[Any]) -> Optional[TransactionReceiptData]:
        """
        通过传入函数名称及参数来调用该合约内的函数。

        参数：
            function_name (str): 函数名称
            *args (Optional[Any]): 函数参数

        返回值：
            transaction_receipt (Optional[TransactionReceiptData]): 交易回执信息
            {"transaction_hash"|"block_number"|"transaction_index"|"transaction_status"|"transaction_type"|"action"|"sender"|"to"|"nonce"|"value"|"gas_used"|"gas_limit"|<"gas_price"|("max_fee_per_gas"&"max_priority_fee_per_gas"&"effective_gas_price")>|("contract_address")|"logs"|"input_data"|"r"|"s"|"v"}
        """

        transaction_data = self.web3py_contract.functions[function_name](*args).build_transaction({"gasPrice": self._eth.gas_price})  # type: ignore
        logger.info(f"\n[Contract][call_function]\n[contract_address]{self.address}\n[function]{function_name}{args}\n{LOG_DIVIDER_LINE}")
        transaction_receipt = self._account.send_transaction(self.address, transaction_data["data"], transaction_data["value"], transaction_data["gasPrice"], transaction_data["gas"])
        return transaction_receipt

    def call_function_with_parameters(self, value: Wei, gas_price: Optional[Wei], gas_limit: int, function_name: str, *args: Optional[Any]) -> Optional[TransactionReceiptData]:
        """
        通过传入函数名称及参数来调用该合约内的函数（可指定发送的原生代币数量、Gas 价格、Gas 最大使用量）。

        参数：
            value (web3.types.Wei): 发送的原生代币数量
            gas_price (Optional[Wei]): Gas 价格
            gas_limit (int): Gas 最大使用量
            function_name (str): 函数名称
            *args (Optional[Any]): 函数参数

        返回值：
            transaction_receipt (Optional[TransactionReceiptData]): 交易回执信息
            {"transaction_hash"|"block_number"|"transaction_index"|"transaction_status"|"transaction_type"|"action"|"sender"|"to"|"nonce"|"value"|"gas_used"|"gas_limit"|<"gas_price"|("max_fee_per_gas"&"max_priority_fee_per_gas"&"effective_gas_price")>|("contract_address")|"logs"|"input_data"|"r"|"s"|"v"}
        """

        transaction_data = self.web3py_contract.functions[function_name](*args).build_transaction({"value": value, "gasPrice": gas_price if gas_price else self._eth.gas_price, "gas": gas_limit})  # type: ignore
        logger.info(
            f"\n[Contract][call_function_with_parameters]\n[contract_address]{self.address}\n[function]{function_name}{args}\n[value]{transaction_data['value']}\n[gas_price]{transaction_data['gasPrice']}\n[gas_limit]{transaction_data['gas']}\n{LOG_DIVIDER_LINE}"
        )
        transaction_receipt = self._account.send_transaction(self.address, transaction_data["data"], transaction_data["value"], transaction_data["gasPrice"], transaction_data["gas"])
        return transaction_receipt

    def read_only_call_function(self, function_name: str, *args: Optional[Any]) -> Optional[Any]:
        """
        通过传入函数名称及参数来调用该合约内的只读函数。

        参数：
            function_name (str): 函数名称
            *args (Optional[Any]): 函数参数

        返回值：
            result (Optional[Any]): 只读函数返回值
        """

        try:
            result = self.web3py_contract.functions[function_name](*args).call()  # type: ignore
            result_print = result.hex() if isinstance(result, HexBytes) else result
            logger.success(
                f"\n[Contract][read_only_call_function]\n[contract_address]{self.address}\n[function]{function_name}{args}\n[result]{result_print}\n{LOG_DIVIDER_LINE}"
            )
            return result
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Contract][read_only_call_function]Failed\n[contract_address]{self.address}\n[function]{function_name}{args}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def encode_function_calldata(self, function_name: str, *args: Optional[Any]) -> Optional[HexStr]:
        """
        通过传入函数名及参数进行编码，生成调用该函数的 CallData 。

        参数：
            function_name (str): 函数名称
            *args (Optional[Any]): 函数参数

        返回值：
            calldata (Optional[HexStr]): 调用数据编码
        """

        try:
            calldata = self.web3py_contract.encodeABI(fn_name=function_name, args=args)
            logger.success(
                f"\n[Contract][encode_function_calldata]\n[contract_address]{self.address}\n[function]{function_name}{args}\n[calldata]{calldata}\n{LOG_DIVIDER_LINE}"
            )
            return calldata
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Contract][encode_function_calldata]Failed\n[contract_address]{self.address}\n[function]{function_name}{args}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    def decode_function_calldata(self, calldata: HexStr) -> Optional[tuple]:
        """
        解码针对当前合约执行调用的 CallData ，得出所调用的函数名称及其参数值。

        参数：
            calldata (HexStr): 对当前合约执行调用的 CallData

        返回值：
            result (Optional[tuple]): 函数名称及其参数值
        """

        try:
            result = self.web3py_contract.decode_function_input(calldata)
            logger.success(
                f"\n[Contract][decode_function_calldata]\n[calldata]{calldata}\n[function]{result[0]}\n[parameters]{result[1]}\n{LOG_DIVIDER_LINE}"
            )
            return result
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Contract][decode_function_calldata]Failed\n[calldata]{calldata}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None


class Utils:
    """
    Utils 是通用工具集，整合了常用的链下操作。静态类,无需实例化。
    """

    @staticmethod
    def set_solidity_version(solidity_version: str) -> None:
        """
        选择 Solidity 版本，若该版本未安装则会自动安装。

        参数：
            solidity_version (str): Solidity 版本号
        """

        try:
            install_solc(solidity_version, show_progress=True)
            set_solc_version(solidity_version)
            version = get_solc_version(True)
            logger.success(f"\n[Utils][set_solidity_version]Current Solidity Version [{version}]\n{LOG_DIVIDER_LINE}")
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][set_solidity_version]Failed\n[solidity_version]{solidity_version}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )

    @staticmethod
    def compile_solidity_contract(file_path: str, contract_name: str, solidity_version: Optional[str] = None, evm_version: Optional[str] = None, optimize: bool = False, optimize_runs: int = 200, base_path: Optional[str] = None, allow_paths: Optional[str] = None) -> Optional[Tuple[dict, HexBytes]]:
        """
        根据给定的参数使用 py-solc-x 编译合约。

        参数：
            file_path (str): 合约代码文件路径
            contract_name (str): 要编译的合约的名称
            solidity_version (Optional[str] = None): 指定使用的 Solidity 版本
            evm_version (Optional[str] = None): 指定编译时使用的 EVM 版本
            optimize (bool = False): 是否开启优化器
            optimize_runs (int = 200): 优化器运行次数参数
            base_path (Optional[str] = None): 指定基础路径
            allow_paths (Optional[str] = None): 指定许可路径

        返回值：
            contract_data (Optional[Tuple[dict, HexBytes]]): 由 ABI 和 Bytecode 组成的元组
        """

        try:
            with open(file_path, "r", encoding="utf-8") as sol:
                compiled_sol = compile_source(
                    sol.read(),
                    solc_version=solidity_version,
                    evm_version=evm_version,
                    optimize=optimize,
                    optimize_runs=optimize_runs,
                    base_path=base_path,
                    allow_paths=allow_paths,
                    output_values=['abi', 'bin']
                )
            contract_data = compiled_sol[f'<stdin>:{contract_name}']
            abi, bytecode = contract_data['abi'], HexBytes(contract_data['bin'])
            contract_data = (abi, bytecode)

            with open(f'{contract_name}ABI.json', 'w', encoding="utf-8") as f:
                dump(abi, f, indent=4)

            logger.success(
                f"\n[Utils][compile_solidity_contract]\n[file_path]{file_path}\n[contract_name]{contract_name}\n[abi]{abi}\n[bytecode]{bytecode.hex()}\n{LOG_DIVIDER_LINE}"
            )
            return contract_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][compile_solidity_contract]Failed\n[file_path]{file_path}\n[contract_name]{contract_name}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def import_contract_abi(file_path: str) -> Optional[dict]:
        """
        导入指定的合约 ABI 文件内容。

        参数：
            file_path (str): ABI 文件完整路径

        返回值：
            abi (Optional[dict]): ABI 内容
        """

        try:
            with open(file_path, 'r', encoding="utf-8") as f:
                abi = load(f)
            logger.success(f"\n[Utils][import_contract_abi]\n[file_path]{file_path}\n[abi]{abi}\n{LOG_DIVIDER_LINE}")
            return abi
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][import_contract_abi]Failed\n[file_path]{file_path}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def generate_new_account() -> Optional[Tuple[ChecksumAddress, HexBytes]]:
        """
        创建新账户。

        返回值：
            account_data (Tuple[ChecksumAddress, HexBytes]): 由账户地址和私钥组成的元组
        """

        try:
            account: LocalAccount = EthAccount.create()
            address = Web3.to_checksum_address(account.address)
            private_key = HexBytes(account.key)
            account_data = (address, private_key)
            logger.success(f"\n[Utils][generate_new_account]\n[address]{address}\n{LOG_DIVIDER_LINE}")
            return account_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][generate_new_account]Failed\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def generate_account_from_mnemonic(mnemonic: str, passphrase: str = "", account_path: str = "m/44'/60'/0'/0/0") -> Optional[Tuple[ChecksumAddress, HexBytes]]:
        """
        将助记词转换为账户地址与私钥。参考 BIP-39 标准。

        参数：
            mnemonic (str): 助记词字符串，以空格分隔
            passphrase (str = ""): 助记词密码，可为空
            account_path (str = "m/44'/60'/0'/0/0"): 分层确定性钱包账户路径

        返回值：
            account_data (Optional[Tuple[ChecksumAddress, HexBytes]]): 由账户地址和私钥组成的元组
        """

        try:
            EthAccount.enable_unaudited_hdwallet_features()
            account = EthAccount.from_mnemonic(mnemonic, passphrase, account_path)
            address = Web3.to_checksum_address(account.address)
            private_key = HexBytes(account.key)
            account_data = (address, private_key)
            logger.success(
                f"\n[Utils][generate_account_from_mnemonic]\n[mnemonic]{mnemonic}\n[passphrase]{passphrase if passphrase else None}\n[account_path]{account_path}\n[address]{address}\n{LOG_DIVIDER_LINE}"
            )
            return account_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][generate_account_from_mnemonic]Failed\n[mnemonic]{mnemonic}\n[passphrase]{passphrase}\n[account_path]{account_path}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def calculate_create_case_contract_address(deployer: ChecksumAddress, nonce: Nonce) -> Optional[ChecksumAddress]:
        """
        计算某账户以 CREATE 方式部署的合约的地址。

        参数：
            deployer (eth_typing.ChecksumAddress): 部署者地址
            nonce (web3.types.Nonce): 部署者发送合约部署交易的 nonce 值

        返回值：
            address (Optional[ChecksumAddress]): 计算出的合约地址
        """

        try:
            address = utils.address.get_create_address(deployer, nonce)
            logger.success(
                f"\n[Utils][calculate_create_case_contract_address]\n[deployer]{deployer}\n[nonce]{nonce}\n[address]{address}\n{LOG_DIVIDER_LINE}"
            )
            return address
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][calculate_create_case_contract_address]Failed\n[deployer]{deployer}\n[nonce]{nonce}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def calculate_create2_case_contract_address(deployer: ChecksumAddress, salt: HexStr, creation_code: HexStr) -> Optional[ChecksumAddress]:
        """
        计算某合约账户以 CREATE2 方式部署的另一个合约的地址。

        参数：
            deployer (eth_typing.ChecksumAddress): 部署者地址（此处应该为合约地址）
            salt (eth_typing.encoding.HexStr): 盐值
            creation_code (eth_typing.encoding.HexStr): 合约的创建时字节码（与运行时字节码不同）

        返回值：
            address (Optional[ChecksumAddress]): 计算出的合约地址
        """

        try:
            address = utils.address.get_create2_address(deployer, salt, creation_code)
            logger.success(
                f"\n[Utils][calculate_create2_case_contract_address]\n[deployer]{deployer}\n[salt]{salt}\n[creation_code]{creation_code}\n[address]{address}\n{LOG_DIVIDER_LINE}"
            )
            return address
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][calculate_create2_case_contract_address]Failed\n[deployer]{deployer}\n[salt]{salt}\n[creation_code]{creation_code}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def generate_signature_data_with_signature(signature: HexBytes) -> Optional[SignatureData]:
        """
        使用签名数据生成 poseidon.evm.SignatureData 对象。

        参数：
            signature (hexbytes.HexBytes): 签名数据

        返回值：
            result (Optional[SignatureData]): 生成结果
            {"signature"|"r"|"s"|"v"}
        """

        try:
            _signature = signature.hex()
            assert (len(_signature) == 130 + 2)
            r = HexBytes('0x' + _signature[2:66])
            s = HexBytes('0x' + _signature[66:-2])
            v = HexBytes('0x' + _signature[-2:])
            result: SignatureData = SignatureData(**{
                "signature": signature,
                "r": r,
                "s": s,
                "v": v
            })
            logger.success(f"\n[Utils][generate_signature_data_with_signature]\n[signature]{_signature}\n[r]{r.hex()}\n[s]{s.hex()}\n[v]{v.hex()}\n{LOG_DIVIDER_LINE}")
            return result
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][generate_signature_data_with_signature]Failed\n[signature]{signature}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def generate_signature_data_with_rsv(r: HexBytes, s: HexBytes, v: HexBytes) -> Optional[SignatureData]:
        """
        使用 R,S,V 生成 poseidon.evm.SignatureData 对象。

        参数：
            r (hexbytes.HexBytes): 签名 r 值
            s (hexbytes.HexBytes): 签名 s 值
            v (hexbytes.HexBytes): 签名 v 值

        返回值：
            result (Optional[SignatureData]): 生成结果
            {"signature"|"r"|"s"|"v"}
        """

        try:
            _r, _s, _v = r.hex(), s.hex(), v.hex()
            assert (len(_r) == 64 + 2 and len(_s) == 64 + 2 and len(_v) == 2 + 2)
            signature = HexBytes('0x' + _r[2:] + _s[2:] + _v[2:])
            result: SignatureData = SignatureData(**{
                "signature": signature,
                "r": r,
                "s": s,
                "v": v
            })
            logger.success(f"\n[Utils][generate_signature_data_with_rsv]\n[r]{_r}\n[s]{_s}\n[v]{_v}\n[signature]{signature.hex()}\n{LOG_DIVIDER_LINE}")
            return result
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][generate_signature_data_with_rsv]Failed\n[r]{r}\n[s]{s}\n[v]{v}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def recover_message_string(message: str, signature: HexBytes) -> Optional[SignedMessageData]:
        """
        通过消息原文和签名还原出签署者的账户地址。

        参数：
            message (str): 消息原文
            signature (hexbytes.HexBytes): 签名

        返回值：
            signed_message_data (Optional[SignedMessageData]): 签名数据
            {"message_hash"|"message"|"signer"|"signature_data"}
        """

        try:
            signable_message = encode_defunct(text=message)
            message_hash = HexBytes(_hash_eip191_message(signable_message))
            signer: ChecksumAddress = Web3.to_checksum_address(EthAccount.recover_message(signable_message, signature=signature))
            signature_data = Utils.generate_signature_data_with_signature(signature)
            signed_message_data = SignedMessageData(**{
                "message_hash": message_hash,
                "message": message,
                "signer": signer,
                "signature_data": signature_data
            })
            logger.success(f"\n[Utils][recover_message_string]\n[message_hash]{message_hash.hex()}\n[message]{message}\n[signer]{signer}\n[signature]{signature_data.signature.hex()}\n[r]{signature_data.r.hex()}\n[s]{signature_data.s.hex()}\n[v]{signature_data.v.hex()}\n{LOG_DIVIDER_LINE}")  # type: ignore
            return signed_message_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][recover_message_string]Failed\n[message]{message}\n[signature]{signature}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def recover_message_raw_hash(message_raw_hash: HexBytes, signature: HexBytes) -> Optional[SignedMessageData]:
        """
        通过消息哈希和签名还原出签署者的账户地址。

        参数：
            message_raw_hash (hexbytes.HexBytes): 消息哈希
            signature (hexbytes.HexBytes): 签名

        返回值：
            signed_message_data (Optional[SignedMessageData]): 签名数据
            {"message_hash"|"message"|"signer"|"signature_data"}
        """

        try:
            signer: ChecksumAddress = Web3.to_checksum_address(EthAccount._recover_hash(message_raw_hash, signature=signature))
            signature_data = Utils.generate_signature_data_with_signature(signature)
            signed_message_data = SignedMessageData(**{
                "message_hash": message_raw_hash,
                "message": None,
                "signer": signer,
                "signature_data": signature_data
            })
            logger.success(
                f"\n[Utils][recover_message_raw_hash]\n[message_raw_hash]{message_raw_hash.hex()}\n[signer]{signer}\n[signature]{signature_data.signature.hex()}\n[r]{signature_data.r.hex()}\n[s]{signature_data.s.hex()}\n[v]{signature_data.v.hex()}\n{LOG_DIVIDER_LINE}"  # type: ignore
            )
            return signed_message_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][recover_message_raw_hash]Failed\n[message_raw_hash]{message_raw_hash}\n[signature]{signature}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def recover_message_hash(message_hash: HexBytes, signature: HexBytes) -> Optional[SignedMessageData]:
        """
        通过消息哈希和签名还原出签署者的账户地址。

        参数：
            message_hash (hexbytes.HexBytes): 消息哈希
            signature (hexbytes.HexBytes): 签名

        返回值：
            signed_message_data (Optional[SignedMessageData]): 签名数据
            {"message_hash"|"message"|"signer"|"signature_data"}
        """

        try:
            signer: ChecksumAddress = Web3.to_checksum_address(EthAccount.recover_message(encode_defunct(hexstr=message_hash.hex()), signature=signature))
            signature_data = Utils.generate_signature_data_with_signature(signature)
            signed_message_data = SignedMessageData(**{
                "message_hash": message_hash,
                "message": None,
                "signer": signer,
                "signature_data": signature_data
            })
            logger.success(
                f"\n[Utils][recover_message_hash]\n[message_hash]{message_hash.hex()}\n[signer]{signer}\n[signature]{signature_data.signature.hex()}\n[r]{signature_data.r.hex()}\n[s]{signature_data.s.hex()}\n[v]{signature_data.v.hex()}\n{LOG_DIVIDER_LINE}"  # type: ignore
            )
            return signed_message_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][recover_message_hash]Failed\n[message_hash]{message_hash}\n[signature]{signature}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def recover_typed_message(domain_data: dict, message_types: dict, message_data: dict, signature: HexBytes) -> Optional[SignedMessageData]:
        """
        通过结构化消息数据和签名还原出签署者的账户地址。

        参数：
            domain_data (dict): 域数据
            message_types (dict): 消息类型定义
            message_data (dict): 消息数据
            signature (hexbytes.HexBytes): 签名

        返回值：
            signed_message_data (Optional[SignedMessageData]): 签名数据
            {"message_hash"|"message"|"signer"|"signature_data"}
        """

        try:
            signable_message = encode_typed_data(domain_data, message_types, message_data)
            message_hash = HexBytes(_hash_eip191_message(signable_message))
            message = f"{domain_data}\n{message_types}\n{message_data}"
            signer: ChecksumAddress = Web3.to_checksum_address(EthAccount.recover_message(signable_message, signature=signature))
            signature_data = Utils.generate_signature_data_with_signature(signature)
            signed_message_data = SignedMessageData(**{
                "message_hash": message_hash,
                "message": message,
                "signer": signer,
                "signature_data": signature_data
            })
            logger.success(
                f"\n[Utils][recover_typed_message]\n[message_hash]{message_hash.hex()}\n[message]\n{message}\n[signer]{signer}\n[signature]{signature_data.signature.hex()}\n[r]{signature_data.r.hex()}\n[s]{signature_data.s.hex()}\n[v]{signature_data.v.hex()}\n{LOG_DIVIDER_LINE}"  # type: ignore
            )
            return signed_message_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][recover_typed_message]Failed\n[domain_data]{domain_data}\n[message_data]{message_data}\n[message_types]{message_types}\n[signature]{signature}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def convert_equivalent_signature(signature: HexBytes) -> Optional[SignatureData]:
        """
        根据 ECDSA 签名可延展性原理，生成另一个等效的签名。

        参数:
            signature (hexbytes.HexBytes): 原始签名

        返回值:
            equivalent_signature (Optional[SignatureData]): 等效签名数据
            {"signature"|"r"|"s"|"v"}
        """

        try:
            original_signature = Utils.generate_signature_data_with_signature(signature)
            s_int = int.from_bytes(original_signature.s, byteorder='big')  # type: ignore
            v_int = int.from_bytes(original_signature.v, byteorder='big')  # type: ignore
            new_s_int = secp256k1.N - s_int
            new_v_int = 28 if v_int == 27 else 27
            new_s_bytes = HexBytes(new_s_int.to_bytes(32, byteorder='big'))
            new_v_bytes = HexBytes(new_v_int.to_bytes(1, byteorder='big'))
            equivalent_signature = Utils.generate_signature_data_with_rsv(original_signature.r, new_s_bytes, new_v_bytes)  # type: ignore
            logger.success(
                f"\n[Utils][convert_equivalent_signature]\n[original_signature]{signature.hex()}\n[equivalent_signature]{equivalent_signature.signature.hex()}\n[r]{equivalent_signature.r.hex()}\n[s]{equivalent_signature.s.hex()}\n[v]{equivalent_signature.v.hex()}\n{LOG_DIVIDER_LINE}"  # type: ignore
            )
            return equivalent_signature
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][convert_equivalent_signature]Failed\n[signature]{signature}\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def assembly_to_bytecode_legacy(assembly: str) -> Optional[HexBytes]:
        """
        将 EVM Assembly 转为 EVM Bytecode 。由于依赖的第三方库 pyevmasm 很久没有更新，所以该功能不一定能支持最新的 EVM 版本。

        参数：
            assembly (str): EVM Assembly

        返回值：
            bytecode (Optional[HexBytes]): EVM Bytecode
        """

        try:
            bytecode = HexBytes(assemble_hex(assembly))
            logger.success(f"\n[Utils][assembly_to_bytecode_legacy]\n[bytecode]{bytecode.hex()}\n{LOG_DIVIDER_LINE}")
            return bytecode
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][assembly_to_bytecode_legacy]Failed\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def bytecode_to_assembly_legacy(bytecode: HexBytes) -> Optional[str]:
        """
        将 EVM Bytecode 转为 EVM Assembly 。由于依赖的第三方库 pyevmasm 很久没有更新，所以该功能不一定能支持最新的 EVM 版本。

        参数：
            bytecode (hexbytes.HexBytes): EVM Bytecode

        返回值：
            assembly (Optional[str]): EVM Assembly 
        """

        try:
            assembly = disassemble_hex(bytecode)
            logger.success(f"\n[Utils][bytecode_to_assembly_legacy]\n[assembly]\n{assembly}\n{LOG_DIVIDER_LINE}")
            return assembly
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Utils][bytecode_to_assembly_legacy]Failed\n[exception_information]{exception_information}\n{LOG_DIVIDER_LINE}"
            )
            return None
