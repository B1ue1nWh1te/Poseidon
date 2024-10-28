"""
本模块主要基于 web3.py 对常用的 EVM 链上交互操作进行了封装。
"""

import os
from dataclasses import dataclass
from decimal import Decimal
from hexbytes import HexBytes
from importlib.metadata import version
from json import dump, dumps
from time import time
from traceback import format_exc
from typing import Any, List, Optional, Union, Sequence

from eth_account import Account as EthAccount
from eth_account.signers.local import LocalAccount
from eth_account.messages import encode_defunct
from loguru import logger
from web3 import HTTPProvider, Web3, utils
from web3.middleware.geth_poa import geth_poa_middleware
from web3.types import BlockIdentifier, _Hash32, Wei, Timestamp, TxData, Nonce, LogReceipt
from eth_typing import (
    BlockNumber,
    ChecksumAddress,
)
from pyevmasm import assemble_hex, disassemble_hex
from solcx import compile_source, get_solc_version, install_solc, set_solc_version

LOG_DIVIDER_LINE = "\n" + "-" * 80

_log_path = os.path.join("logs", "poseidon_evm_{time}.log")
_version = version("poseidon-python")
logger.add(_log_path)
logger.success(f"\n[Poseidon]Current Version [{_version}]{LOG_DIVIDER_LINE}")


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


class Chain():
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

        request_params_print = f"\n[request_params]{request_params}" if request_params else ""
        start_time = time()
        self.provider = Web3(HTTPProvider(rpc_url, request_kwargs=request_params))
        if self.provider.is_connected():
            self.provider.middleware_onion.inject(geth_poa_middleware, layer=0)
            self.eth = self.provider.eth
            self.chain_id = self.eth.chain_id
            finish_time = time()
            delay = round((finish_time - start_time) * 1000)
            logger.success(f"\n[Chain][__init__]Connected to [{rpc_url}] [{delay} ms]{request_params_print}{LOG_DIVIDER_LINE}")
            self.get_chain_information(False, False)
        else:
            logger.error(f"\n[Chain][__init__]Failed to connect to [{rpc_url}]{request_params_print}{LOG_DIVIDER_LINE}")
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
            timeslot = int(self.eth.get_block(block_number).get("timestamp", 0) - self.eth.get_block(block_number - 100).get("timestamp", 0))/100
            timeslot_print = f"\n[timeslot]{timeslot}s"

        client_version_print = ""
        if show_client_version:
            client_version = self.provider.client_version
            client_version_print = f"\n[client_version]{client_version}"

        chain_information: ChainInformationData = ChainInformationData(**{
            "chain_id": chain_id,
            "block_number": block_number,
            "gas_price": gas_price,
            "timeslot": timeslot if show_timeslot else None,
            "client_version": client_version if show_client_version else None
        })
        logger.success(
            f"\n[Chain][get_chain_information]\n[chain_id]{chain_id}\n[block_number]{block_number}\n[gas_price]{Web3.from_wei(gas_price, 'gwei')} Gwei{timeslot_print}{client_version_print}{LOG_DIVIDER_LINE}"
        )
        return chain_information

    def get_block_information(self, block_id: BlockIdentifier) -> BlockInformationData:
        """
        根据区块 ID 获取该区块基本信息。

        参数：
            block_id (web3.types.BlockIdentifier): 区块 ID (可为具体区块号、区块哈希或 'latest','earliest'，'pending' 等标识符)

        返回值：
            block_information (poseidon.evm.BlockInformationData): 区块基本信息
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

            block_information: BlockInformationData = BlockInformationData(**{
                "block_hash": block_hash,
                "block_number": block_number,
                "timestamp": timestamp,
                "miner": miner,
                "gas_used": gas_used,
                "gas_limit": gas_limit,
                "transactions": transactions
            })
            logger.success(
                f"\n[Chain][get_block_information]\n[block_hash]{block_hash.hex()}\n[block_number]{block_number}\n[timestamp]{timestamp}\n[miner]{miner}\n[gas_used]{gas_used}\n[gas_limit]{gas_limit}\n[transactions]{transactions}{LOG_DIVIDER_LINE}"
            )
            return block_information
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Chain][get_block_information]Failed\n[block_id]{block_id}\n[exception_information]{exception_information}{LOG_DIVIDER_LINE}"
            )
            return BlockInformationData(**{})

    def get_transaction_receipt_by_hash(self, transaction_hash: _Hash32) -> TransactionReceiptData:
        """
        根据交易哈希获取该交易的回执信息。

        参数：
            transaction_hash (_Hash32): 交易哈希

        返回值：
            transaction_receipt (poseidon.evm.TransactionReceiptData): 交易回执信息
            {"transaction_hash"|"block_number"|"transaction_index"|"transaction_status"|"transaction_type"|"action"|"sender"|"to"|"nonce"|"value"|"gas_used"|"gas_limit"|<"gas_price"|("max_fee_per_gas"&"max_priority_fee_per_gas"&"effective_gas_price")>|("contract_address")|"logs"|"input_data"|"r"|"s"|"v"}
        """

        try:
            info = self.eth.wait_for_transaction_receipt(transaction_hash, timeout=60, poll_latency=0.5)
            block_number = info.get("blockNumber")
            transaction_index = info.get("transactionIndex")
            transaction_status = info.get("status")
            transaction_type = info.get("type")
            sender = info.get("from")
            to = info.get("to")
            effective_gas_price = info.get("effectiveGasPrice")
            gas_used = info.get("gasUsed")
            _contract_address = info.get("contractAddress")
            contract_address = _contract_address if _contract_address else None
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

            transaction_receipt: TransactionReceiptData = TransactionReceiptData(**{
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
            _transaction_type = "EIP-155" if transaction_type == 0 else "EIP-2930" if transaction_type == 1 else "EIP-1559" if transaction_type == 2 else "EIP-4844" if transaction_type == 3 else "Unknown"
            gas_price_print = f"\n[max_fee_per_gas]{Web3.from_wei(max_fee_per_gas, 'gwei')} Gwei\n[max_priority_fee_per_gas]{Web3.from_wei(max_priority_fee_per_gas, 'gwei')} Gwei\n[effective_gas_price]{Web3.from_wei(effective_gas_price, 'gwei')} Gwei" if _transaction_type == "EIP-1559" or _transaction_type == "EIP-4844" else f"\n[gas_price]{Web3.from_wei(gas_price, 'gwei')} Gwei"
            contract_address_print = f"\n[contract_address]{contract_address}" if contract_address else ""

            general_print = f"\n[Chain][get_transaction_receipt_by_hash]\n[transaction_hash]{_transaction_hash.hex()}\n[block_number]{block_number}\n[transaction_index]{transaction_index}\n[status]{_transaction_status}\n[transaction_type]{_transaction_type}\n[action]{action}\n[sender]{sender}\n[to]{to}\n[nonce]{nonce} [value]{value}\n[gas_used]{gas_used} [gas_limit]{gas_limit}{gas_price_print}{contract_address_print}\n[logs]{logs}\n[input_data]{input_data.hex()}\n[r]{r.hex()}\n[s]{s.hex()}\n[v]{v.hex()}{LOG_DIVIDER_LINE}"

            if transaction_status:
                logger.success(general_print)
            else:
                logger.error(general_print)

            return transaction_receipt
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Chain][get_transaction_receipt_by_hash]Failed\n[transaction_hash]{transaction_hash}\n[exception_information]{exception_information}{LOG_DIVIDER_LINE}"
            )
            return TransactionReceiptData(**{})

    def get_transaction_information_by_block_id_and_index(self, block_id: BlockIdentifier, transaction_index: int) -> TransactionReceiptData:
        """
        根据区块 ID 和索引来获取该交易的回执信息。

        参数：
            block_id (web3.types.BlockIdentifier): 区块 ID (可为具体区块号、区块哈希或 'latest','earliest'，'pending' 等标识符)
            transaction_index (int): 索引

        返回值：
            transaction_receipt (poseidon.evm.TransactionReceiptData): 交易回执信息
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

            receipt = self.eth.get_transaction_receipt(transaction_hash)
            transaction_status = receipt.get("status")
            transaction_type = receipt.get("type")
            gas_used = receipt.get("gasUsed")
            effective_gas_price = receipt.get("effectiveGasPrice")
            contract_address = receipt.get("contractAddress")
            logs = receipt.get("logs")

            transaction_information: TransactionReceiptData = TransactionReceiptData(**{
                "transaction_hash": transaction_hash,
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
            _transaction_type = "EIP-155" if transaction_type == 0 else "EIP-2930" if transaction_type == 1 else "EIP-1559" if transaction_type == 2 else "EIP-4844" if transaction_type == 3 else "Unknown"
            gas_price_print = f"\n[max_fee_per_gas]{Web3.from_wei(max_fee_per_gas, 'gwei')} Gwei\n[max_priority_fee_per_gas]{Web3.from_wei(max_priority_fee_per_gas, 'gwei')} Gwei\n[effective_gas_price]{Web3.from_wei(effective_gas_price, 'gwei')} Gwei" if _transaction_type == "EIP-1559" or _transaction_type == "EIP-4844" else f"\n[gas_price]{Web3.from_wei(gas_price, 'gwei')} Gwei"
            contract_address_print = f"\n[contract_address]{contract_address}" if contract_address else ""

            general_print = f"\n[Chain][get_transaction_information_by_block_id_and_index]\n[transaction_hash]{transaction_hash.hex()}\n[block_number]{block_number}\n[transaction_index]{transaction_index}\n[status]{_transaction_status}\n[transaction_type]{_transaction_type}\n[action]{action}\n[sender]{sender}\n[to]{to}\n[nonce]{nonce} [value]{value}\n[gas_used]{gas_used} [gas_limit]{gas_limit}{gas_price_print}{contract_address_print}\n[logs]{logs}\n[input_data]{input_data.hex()}\n[r]{r.hex()}\n[s]{s.hex()}\n[v]{v.hex()}{LOG_DIVIDER_LINE}"

            if transaction_status:
                logger.success(general_print)
            else:
                logger.error(general_print)

            return transaction_information
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Chain][get_transaction_information_by_block_id_and_index]Failed\n[block_id]{block_id}\n[transaction_index]{transaction_index}\n[exception_information]{exception_information}{LOG_DIVIDER_LINE}"
            )
            return TransactionReceiptData(**{})

    def get_balance(self, address: ChecksumAddress) -> Wei:
        """
        根据账户地址获取其原生代币余额。

        参数：
            address (ChecksumAddress): 账户地址

        返回值：
            balance (Wei): 账户原生代币余额
        """

        try:
            _address = Web3.to_checksum_address(address)
            balance = self.eth.get_balance(_address, block_identifier="latest")
            logger.success(
                f"\n[Chain][get_balance]\n[address]{_address}\n[balance][{balance} Wei]<=>[{Web3.from_wei(balance,'ether')} Ether]{LOG_DIVIDER_LINE}"
            )
            return balance
        except Exception:
            exception_information = format_exc()
            logger.error(f"\n[Chain][get_balance]Failed\n[address]{address}\n[exception_information]{exception_information}{LOG_DIVIDER_LINE}")
            return Wei(0)

    def get_code(self, address: ChecksumAddress) -> HexBytes:
        """
        根据合约地址获取其字节码。

        参数：
            address (ChecksumAddress): 合约地址

        返回值：
            bytecode (HexBytes): 合约字节码
        """

        try:
            _address = Web3.to_checksum_address(address)
            bytecode = self.eth.get_code(_address, block_identifier="latest")
            logger.success(f"\n[Chain][get_code]\n[address]{_address}\n[bytecode]{bytecode.hex()}{LOG_DIVIDER_LINE}")
            return bytecode
        except Exception:
            exception_information = format_exc()
            logger.error(f"\n[Chain][get_code]Failed\n[address]{address}\n[exception_information]{exception_information}{LOG_DIVIDER_LINE}")
            return HexBytes("")

    def get_storage(self, address: ChecksumAddress, slot_index: int) -> HexBytes:
        """
        根据合约地址和存储插槽索引获取存储值。

        参数：
            address (ChecksumAddress): 合约地址
            slot_index (int): 存储插槽索引

        返回值：
            storage_data (HexBytes): 存储值
        """

        try:
            _address = Web3.to_checksum_address(address)
            storage_data = self.eth.get_storage_at(_address, slot_index, block_identifier="latest")
            logger.success(
                f"\n[Chain][get_storage]\n[address]{_address}\n[slot_index]{slot_index}\n[storage_data]{storage_data.hex()}{LOG_DIVIDER_LINE}"
            )
            return storage_data
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Chain][get_storage]Failed\n[address]{address}\n[slot_index]{slot_index}\n[exception_information]{exception_information}{LOG_DIVIDER_LINE}"
            )
            return HexBytes("")

    def dump_storage(self, address: ChecksumAddress, start_slot_index: int, end_slot_index: int) -> List[HexBytes]:
        """
        根据合约地址和指定起止插槽索引，批量获取存储值。

        参数：
            address (ChecksumAddress): 合约地址
            start_slot_index (int): 起始插槽索引
            end_slot_index (int): 终止插槽索引

        返回值：
            storage_data_list (List[HexBytes]): 存储值列表
        """

        try:
            _address = Web3.to_checksum_address(address)
            latest_block_number = self.eth.get_block_number()
            storage_data_list = [self.eth.get_storage_at(_address, i, block_identifier=latest_block_number) for i in range(start_slot_index, end_slot_index)]
            storage_data_list_print = '\n'.join([f"[slot {i}]{storage_data_list[i].hex()}" for i in range(len(storage_data_list))])
            logger.success(f"\n[Chain][dump_storage]\n[address]{_address}\n{storage_data_list_print}{LOG_DIVIDER_LINE}")
            return storage_data_list
        except Exception:
            exception_information = format_exc()
            logger.error(
                f"\n[Chain][dump_storage]Failed\n[address]{address}\n[start_slot_index]{start_slot_index}\n[end_slot_index]{end_slot_index}\n[exception_information]{exception_information}{LOG_DIVIDER_LINE}"
            )
            return []


class Account():
    """
    Account 是账户实例，后续的交易将由该账户签署并发送至链上。
    """

    def __init__(self, chain: Chain, private_key: HexBytes) -> None:
        """
        实例初始化。通过私钥导入账户并与 Chain 实例绑定。

        参数：
            chain (poseidon.evm.Chain): EVM 链实例
            private_key (HexBytes): 账户私钥

        成员变量：
            eth_account (eth_account.signers.local.LocalAccount): eth_account 的 LocalAccount 实例
            address (ChecksumAddress): 账户地址
            private_key (HexBytes): 账户私钥
        """

        try:
            self.eth_account: LocalAccount = EthAccount.from_key(private_key)
            self.address = ChecksumAddress(self.eth_account.address)
            self.private_key = HexBytes(self.eth_account.key)
            self._chain = chain
            self._chain.eth.default_account = self.address
            logger.success(f"\n[Account][__init__]Successfully import account [{self.address}]{LOG_DIVIDER_LINE}")
            self.set_need_enter_confirm_before_send_transaction(False)
            self.get_self_balance()
        except Exception:
            exception_information = format_exc()
            logger.error(f"\n[Account][__init__]Failed to import account\n[exception_information]{exception_information}{LOG_DIVIDER_LINE}")
            raise Exception("Failed to import account.")

    def set_need_enter_confirm_before_send_transaction(self, need_enter_confirm: bool = True) -> None:
        """
        设置在通过该账户发送每一笔交易之前是否需要控制台回车确认。开启后会在每笔交易即将发送前暂停流程，在控制台询问是否发送该笔交易。

        参数：
            need_enter_confirm (bool): 是否需要控制台回车确认
        """

        self._need_enter_confirm = need_enter_confirm
        if self._need_enter_confirm:
            logger.success(f"\n[Account][set_need_enter_confirm_before_send_transaction][True]{LOG_DIVIDER_LINE}")
        else:
            logger.warning(f"\n[Account][set_need_enter_confirm_before_send_transaction][False]{LOG_DIVIDER_LINE}")

    def get_self_balance(self) -> Wei:
        """
        获取当前账户的原生代币余额。

        返回值：
            balance (Wei): 当前账户的原生代币余额
        """

        balance = self._chain.get_balance(self.address)
        if balance == 0:
            logger.warning(f"\n[Account][get_self_balance]\n[warning]This account's balance is zero{LOG_DIVIDER_LINE}")
        return balance

    def transfer(self, to: ChecksumAddress, value: Wei, data: HexBytes = HexBytes("0x"), gas_price: Optional[Wei] = None, gas_limit: int = 100000) -> TransactionReceiptData:
        """
        向指定账户转账指定数量的网络原生代币，可附带信息。若 120 秒内交易未确认则作超时处理。

        参数：
            To (str): 接收方地址
            Value (int): 发送的网络原生代币数量，单位为 wei 。
            Data (可选)(str): 交易数据。含 0x 前缀的十六进制形式。默认值为 "0x" 。
            GasPrice (可选)(Optional[int]): Gas 价格，单位为 wei ，默认使用 RPC 建议的 gas_price 。
            GasLimit (可选)(int): Gas 最大使用量，单位为 wei ，默认为 100000 wei 。

        返回值：
            TransactionInformation (poseidon.evm.TransactionReceiptData): 交易信息，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
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
                "gasPrice": GasPrice if GasPrice else self._chain.eth.gas_price,
                "nonce": self._chain.eth.get_transaction_count(From),
                "data": Data,
            }
            SignedTxn = self.EthAccount.sign_transaction(Txn)
            Txn["gasPrice"] = f'{Web3.from_wei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][Transfer]\n[Txn]{dumps(Txn, indent=2)}\n{LOG_DIVIDER_LINE}")
            if self._Request:
                logger.warning(f"\n[Account][RequestAuthorizationBeforeSendTransaction][True]\nDo you confirm sending this transaction?")
                Command = input("Command Input (yes/1/[Enter] or no/0):")
                if Command == "no" or Command == "0" or (len(Command) > 0 and Command != "yes" and Command != "1"):
                    raise Exception("Cancel sending transaction.")
            print("pending...")
            TransactionHash = self._chain.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            TransactionInformation = self._Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][Transfer]Failed\n[From]{From}\n[To]{To}\n[Value]{Value}\n[GasPrice]{GasPrice}\n[GasLimit]{GasLimit}\n[Data]{Data}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    def SendTransaction(self, To: str, Data: str, Value: int = 0, GasPrice: Optional[int] = None, GasLimit: int = 1000000) -> TransactionReceiptData:
        """
        以传统方式发送一笔自定义交易。若 120 秒内交易未确认则作超时处理。

        参数：
            To (str): 接收方地址
            Data (str): 交易数据。含 0x 前缀的十六进制形式。
            Value (可选)(int): 随交易发送的网络原生代币数量，单位为 wei ，默认为 0 wei 。
            GasPrice (可选)(Optional[int]): Gas 价格，单位为 wei ，默认使用 RPC 建议的 gas_price 。
            GasLimit (可选)(int): Gas 最大使用量，单位为 wei ，默认为 1000000 wei 。

        返回值：
            TransactionInformation (poseidon.evm.TransactionReceiptData): 交易信息，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
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
                "gasPrice": GasPrice if GasPrice else self._chain.eth.gas_price,
                "nonce": self._chain.eth.get_transaction_count(From),
                "data": Data,
            }
            SignedTxn = self.EthAccount.sign_transaction(Txn)
            Txn["gasPrice"] = f'{Web3.from_wei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][SendTransaction][Traditional]\n[Txn]{dumps(Txn, indent=2)}\n{LOG_DIVIDER_LINE}")
            if self._Request:
                logger.warning(f"\n[Account][RequestAuthorizationBeforeSendTransaction][True]\nDo you confirm sending this transaction?")
                Command = input("Command Input (yes/1/[Enter] or no/0):")
                if Command == "no" or Command == "0" or (len(Command) > 0 and Command != "yes" and Command != "1"):
                    raise Exception("Cancel sending transaction.")
            print("pending...")
            TransactionHash = self._chain.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            TransactionInformation = self._Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][SendTransaction][EIP-155]Failed\n[From]{From}\n[To]{To}\n[Value]{Value}\n[GasPrice]{GasPrice}\n[GasLimit]{GasLimit}\n[Data]{Data}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    def SendTransactionByEIP1559(self, To: str, Data: str, Value: int = 0, BaseFee: Optional[int] = None, MaxPriorityFee: Optional[int] = None, GasLimit: int = 1000000) -> TransactionReceiptData:
        """
        以 EIP-1559 方式发送一笔自定义交易。若 120 秒内交易未确认则作超时处理。

        参数：
            To (str): 接收方地址
            Data (str): 交易数据。含 0x 前缀的十六进制形式。
            Value (可选)(int): 随交易发送的网络原生代币数量，单位为 wei ，默认为 0 wei 。
            BaseFee (可选)(Optional[int]): BaseFee 价格，单位为 wei ，默认使用 RPC 建议的 gas_price 。
            MaxPriorityFee (可选)(Optional[int]): MaxPriorityFee 价格，单位为 wei ，默认使用 RPC 建议的 max_priority_fee 。
            GasLimit (可选)(int): Gas 最大使用量，单位为 wei ，默认为 1000000 wei 。

        返回值：
            TransactionInformation (poseidon.evm.TransactionReceiptData): 交易信息，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """

        try:
            From = self.EthAccount.address
            To = Web3.to_checksum_address(To)
            BaseFee = BaseFee if BaseFee else self._chain.eth.gas_price
            MaxPriorityFee = MaxPriorityFee if MaxPriorityFee else self._chain.eth.max_priority_fee
            Txn = {
                "chainId": self._Chain.ChainId,
                "from": From,
                "to": To,
                "value": Value,
                "gas": GasLimit,
                "maxFeePerGas": BaseFee + MaxPriorityFee,
                "maxPriorityFeePerGas": MaxPriorityFee,
                "nonce": self._chain.eth.get_transaction_count(From),
                "data": Data
            }
            SignedTxn = self.EthAccount.sign_transaction(Txn)
            Txn["maxFeePerGas"] = f'{Web3.from_wei(Txn["maxFeePerGas"],"gwei")} Gwei'
            Txn["maxPriorityFeePerGas"] = f'{Web3.from_wei(Txn["maxPriorityFeePerGas"],"gwei")} Gwei'
            logger.info(f"\n[Account][SendTransaction][EIP-1559]\n[Txn]{dumps(Txn, indent=2)}\n{LOG_DIVIDER_LINE}")
            if self._Request:
                logger.warning(f"\n[Account][RequestAuthorizationBeforeSendTransaction][True]\nDo you confirm sending this transaction?")
                Command = input("Command Input (yes/1/[Enter] or no/0):")
                if Command == "no" or Command == "0" or (len(Command) > 0 and Command != "yes" and Command != "1"):
                    raise Exception("Cancel sending transaction.")
            print("pending...")
            TransactionHash = self._chain.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            TransactionInformation = self._Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][SendTransaction][EIP-1559]Failed\n[From]{From}\n[To]{To}\n[Value]{Value}\n[BaseFee]{BaseFee}\n[MaxPriorityFee]{MaxPriorityFee}\n[GasLimit]{GasLimit}\n[Data]{Data}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    def DeployContract(self, ABI: dict, Bytecode: str, Value: int = 0, GasPrice: Optional[int] = None, *Arguments: Optional[Any]) -> TransactionReceiptData:
        """
        部署合约。若 120 秒内交易未确认则作超时处理。

        参数：
            ABI (dict): 合约 ABI 
            Bytecode (str): 合约部署字节码。
            Value (可选)(int): 随交易发送给合约的网络原生代币数量，单位为 wei ，默认为 0 wei 。
            GasPrice (可选)(Optional[int]): Gas 价格，单位为 wei ，默认使用 RPC 建议的 gas_price 。
            *Arguments (可选)(Optional[Any]): 传给合约构造函数的参数，默认为空。

        返回值：
            TransactionInformation (poseidon.evm.TransactionReceiptData): 交易信息，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
            当合约部署成功时，返回值中会额外添加"Contract"字段，该变量是已实例化的 Contract 对象，若失败则为 None。
        """

        try:
            DeployingContract = self._chain.eth.contract(abi=ABI, bytecode=Bytecode)
            TransactionData = DeployingContract.constructor(*Arguments).build_transaction({"value": Value, "gasPrice": GasPrice if GasPrice else self._chain.eth.gas_price})
            Txn = {
                "chainId": self._Chain.ChainId,
                "from": self.EthAccount.address,
                "value": TransactionData["value"],
                "gas": TransactionData["gas"],
                "gasPrice": TransactionData["gasPrice"],
                "nonce": self._chain.eth.get_transaction_count(self.EthAccount.address),
                "data": TransactionData["data"]
            }
            SignedTxn = self.EthAccount.sign_transaction(Txn)
            Txn["gasPrice"] = f'{Web3.from_wei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][DeployContract]\n[Txn]{dumps(Txn, indent=2)}\n{LOG_DIVIDER_LINE}")
            if self._Request:
                logger.warning(f"\n[Account][RequestAuthorizationBeforeSendTransaction][True]\nDo you confirm sending this transaction?")
                Command = input("Command Input (yes/1/[Enter] or no/0):")
                if Command == "no" or Command == "0" or (len(Command) > 0 and Command != "yes" and Command != "1"):
                    raise Exception("Cancel sending transaction.")
            print("pending...")
            TransactionHash = self._chain.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            TransactionInformation = self._Chain.GetTransactionInformationByHash(TransactionHash)
            if TransactionInformation.Status:
                DeployedContract = Contract(self, TransactionInformation.ContractAddress, ABI)
                TransactionInformation.Contract = DeployedContract
                return TransactionInformation
            else:
                TransactionInformation.Contract = None
                return TransactionInformation
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][DeployContract]Failed\n[Value]{Value}\n[GasPrice]{GasPrice}\n[ABI]{ABI}\n[Bytecode]{Bytecode}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    def DeployContractWithoutABI(self, Bytecode: str, Value: int = 0, GasPrice: Optional[int] = None, GasLimit: int = 3000000) -> TransactionReceiptData:
        """
        在没有 ABI 的情况下，仅使用字节码来部署合约。若 120 秒内交易未确认则作超时处理。

        参数：
            Bytecode (str): 合约部署字节码。
            Value (可选)(int): 随交易发送给合约的网络原生代币数量，单位为 wei ，默认为 0 wei 。
            GasPrice (可选)(Optional[int]): Gas 价格，单位为 wei ，默认使用 RPC 建议的 gas_price 。
            GasLimit (可选)(int): Gas 最大使用量，单位为 wei ，默认为 3000000 wei 。

        返回值：
            TransactionInformation (poseidon.evm.TransactionReceiptData): 交易信息，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """

        try:
            Txn = {
                "chainId": self._Chain.ChainId,
                "from": self.EthAccount.address,
                "value": Value,
                "gas": GasLimit,
                "gasPrice": GasPrice if GasPrice else self._chain.eth.gas_price,
                "nonce": self._chain.eth.get_transaction_count(self.EthAccount.address),
                "data": Bytecode,
            }
            SignedTxn = self.EthAccount.sign_transaction(Txn)
            Txn["gasPrice"] = f'{Web3.from_wei(Txn["gasPrice"],"gwei")} Gwei'
            logger.info(f"\n[Account][DeployContractWithoutABI]\n[Txn]{dumps(Txn, indent=2)}\n{LOG_DIVIDER_LINE}")
            if self._Request:
                logger.warning(f"\n[Account][RequestAuthorizationBeforeSendTransaction][True]\nDo you confirm sending this transaction?")
                Command = input("Command Input (yes/1/[Enter] or no/0):")
                if Command == "no" or Command == "0" or (len(Command) > 0 and Command != "yes" and Command != "1"):
                    raise Exception("Cancel sending transaction.")
            print("pending...")
            TransactionHash = self._chain.eth.send_raw_transaction(SignedTxn.rawTransaction).hex()
            TransactionInformation = self._Chain.GetTransactionInformationByHash(TransactionHash)
            return TransactionInformation
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][DeployContractWithoutABI]Failed\n[Value]{Value}\n[GasPrice]{GasPrice}\n[GasLimit]{GasLimit}\n[Bytecode]{Bytecode}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    def SignMessage(self, Message: str) -> SignedMessageData:
        """
        消息字符串进行签名。

        参数：
            Message (str): 待签名消息字符串

        返回值：
            SignatureData (poseidon.evm.SignedMessageData): 签名数据。当出现异常时返回 None 。
            {"SignerAddress"|"Message"|"MessageHash"|"Signature"|"R"|"S"|"V"}
        """

        try:
            SignerAddress = str(self.EthAccount.address)
            SignedMessage = self.EthAccount.sign_message(encode_defunct(text=Message))
            MessageHash = str(SignedMessage.messageHash.hex())
            Signature = str(SignedMessage.signature.hex())
            R = f"0x{int(hex(SignedMessage.r), 16):0>64x}"
            S = f"0x{int(hex(SignedMessage.s), 16):0>64x}"
            V = f"0x{int(hex(SignedMessage.v), 16):0>2x}"
            logger.success(
                f"\n[Account][SignMessage]\n[SignerAddress]{SignerAddress}\n[Message]{Message}\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[R]{R}\n[S]{S}\n[V]{V}\n{LOG_DIVIDER_LINE}"
            )
            SignatureData: SignedMessageData = SignedMessageData(**{
                "SignerAddress": SignerAddress,
                "Message": Message,
                "MessageHash": MessageHash,
                "Signature": Signature,
                "R": R,
                "S": S,
                "V": V
            })
            return SignatureData
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][SignMessage]Failed to sign message\n[SignerAddress]{SignerAddress}\n[Message]{Message}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    def SignMessageHash(self, MessageHash: str) -> SignedMessageData:
        """
        对消息哈希进行签名。

        参数：
            MessageHash (str): 待签名消息哈希

        返回值：
            SignatureData (poseidon.evm.SignedMessageData): 签名数据。当出现异常时返回 None 。
            {"SignerAddress"|"MessageHash"|"Signature"|"R"|"S"|"V"}
        """

        try:
            SignerAddress = str(self.EthAccount.address)
            SignedMessage = self.EthAccount.signHash(MessageHash)
            MessageHash = str(SignedMessage.messageHash.hex())
            Signature = str(SignedMessage.signature.hex())
            R = f"0x{int(hex(SignedMessage.r), 16):0>64x}"
            S = f"0x{int(hex(SignedMessage.s), 16):0>64x}"
            V = f"0x{int(hex(SignedMessage.v), 16):0>2x}"
            logger.success(
                f"\n[Account][SignMessageHash]\n[SignerAddress]{SignerAddress}\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[R]{R}\n[S]{S}\n[V]{V}\n{LOG_DIVIDER_LINE}"
            )
            SignatureData: SignedMessageData = SignedMessageData(**{
                "SignerAddress": SignerAddress,
                "Message": None,
                "MessageHash": MessageHash,
                "Signature": Signature,
                "R": R,
                "S": S,
                "V": V
            })
            return SignatureData
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Account][SignMessageHash]Failed\n[SignerAddress]{SignerAddress}\n[MessageHash]{MessageHash}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
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
            Account (poseidon.evm.Account): 账户实例
            Address (str): 合约地址
            ABI (str): 合约 ABI

        成员变量：
            Instance (Web3.eth.Contract): web3.py 原生 contract 对象实例
            Address (str): 合约地址
        """

        try:
            self._Account, self._chain.eth, self.Address = Account, Account._Eth, Web3.to_checksum_address(Address)
            self.Instance = self._chain.eth.contract(address=self.Address, abi=ABI)
            logger.success(f"\n[Contract][Initialize]Successfully instantiated contract [{self.Address}]\n{LOG_DIVIDER_LINE}")
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Contract][Initialize]Failed to instantiated contract [{self.Address}]\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            raise Exception("Failed to instantiate contract.")

    def CallFunction(self, FunctionName: str, *FunctionArguments: Optional[Any]) -> TransactionReceiptData:
        """
        通过传入函数名及参数来调用该合约内的函数。

        参数：
            FunctionName (str): 函数名称
            *FunctionArguments (可选)(Optional[Any]): 函数参数，默认为空。

        返回值：
            TransactionInformation (poseidon.evm.TransactionReceiptData): 交易信息，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """

        TransactionData = self.Instance.functions[FunctionName](*FunctionArguments).build_transaction({"gasPrice": self._chain.eth.gas_price})
        logger.info(f"\n[Contract][CallFunction]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n{LOG_DIVIDER_LINE}")
        TransactionInformation = self._Account.SendTransaction(self.Address, TransactionData["data"], TransactionData["value"], TransactionData["gasPrice"], TransactionData["gas"])
        return TransactionInformation

    def CallFunctionWithParameters(self, Value: int, GasPrice: Optional[int], GasLimit: int, FunctionName: str, *FunctionArguments: Optional[Any]) -> TransactionReceiptData:
        """
        通过传入函数名及参数来调用该合约内的函数。支持自定义 Value 和 GasLimit 。

        参数：
            Value (int): 随交易发送的网络原生代币数量，单位为 wei 。
            GasPrice (Optional[int]): Gas 价格，单位为 wei ，默认使用 RPC 建议的 gas_price 。
            GasLimit (int): Gas 最大使用量，单位为 wei 。
            FunctionName (str): 函数名称
            *FunctionArguments (Optional[Any]): 函数参数，默认为空。

        返回值：
            TransactionInformation (poseidon.evm.TransactionReceiptData): 交易信息，通过 Chain.GetTransactionInformationByHash 获取。当出现异常时返回 None 。
        """

        TransactionData = self.Instance.functions[FunctionName](*FunctionArguments).build_transaction({"value": Value, "gasPrice": GasPrice if GasPrice else self._chain.eth.gas_price, "gas": GasLimit})
        logger.info(
            f"\n[Contract][CallFunctionWithValueAndGasLimit]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[Value]{TransactionData['value']}\n[GasPrice]{TransactionData['gasPrice']}\n[GasLimit]{TransactionData['gas']}\n{LOG_DIVIDER_LINE}"
        )
        TransactionInformation = self._Account.SendTransaction(self.Address, TransactionData["data"], TransactionData["value"], TransactionData["gasPrice"], TransactionData["gas"])
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
                f"\n[Contract][ReadOnlyCallFunction]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[Result]{Result}\n{LOG_DIVIDER_LINE}"
            )
            return Result
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Contract][ReadOnlyCallFunction]Failed\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
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
            CallData = str(self.Instance.encodeABI(fn_name=FunctionName, args=FunctionArguments))
            logger.success(
                f"\n[Contract][EncodeABI]\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[CallData]{CallData}\n{LOG_DIVIDER_LINE}"
            )
            return CallData
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Contract][EncodeABI]Failed\n[ContractAddress]{self.Address}\n[Function]{FunctionName}{FunctionArguments}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    def DecodeFunctionInputData(self, InputData: str) -> tuple:
        """
        解码对当前合约执行调用的 InputData ，得出所调用的函数及其参数值。

        参数：
            InputData (str): 对当前合约执行调用的 InputData 

        返回值：
            Result (tuple): 函数及其参数值
        """

        try:
            Result = self.Instance.decode_function_input(InputData)
            logger.success(
                f"\n[Contract][DecodeFunctionInputData]\n[InputData]{InputData}\n[Function]{Result[0]}\n[Parameters]{Result[1]}\n{LOG_DIVIDER_LINE}"
            )
            return Result
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[Contract][DecodeFunctionInputData]Failed\n[InputData]{InputData}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None


class Utils():
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
            install_solc(SolidityVersion, True)
            set_solc_version(SolidityVersion)
            SolidityVersion = get_solc_version(True)
            logger.success(f"\n[BlockchainUtils][SwitchSolidityVersion]Current Solidity Version [{SolidityVersion}]\n{LOG_DIVIDER_LINE}")
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][SwitchSolidityVersion]Failed to switch to version [{SolidityVersion}]\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )

    @staticmethod
    def Compile(FileCourse: str, ContractName: str, SolidityVersion: Optional[str] = None, Optimize: Optional[bool] = None, OptimizeRuns: Optional[int] = None, BasePaths: Optional[str] = None, AllowPaths: Optional[str] = None, EvmVersion: Optional[str] = None) -> tuple:
        """
        根据给定的参数使用 py-solc-x 编译合约。当编译失败时会抛出异常。

        参数：
            FileCourse (str): 合约文件完整路径。当合约文件与脚本文件在同一目录下时可直接使用文件名。
            ContractName (str): 要编译的合约名称
            SolidityVersion (可选)(Optional[str]): 指定使用的 Solidity 版本。若不指定则会使用当前已激活的 Solidity 版本进行编译。默认为 None ，使用目前已激活的 solc 版本。
            Optimize (可选)(bool): 是否开启优化器。默认为 None ，不开启优化器。
            OptimizeRuns (可选)(int): 优化运行次数。默认为 None ，不开启优化器。
            BasePaths (可选)(Optional[str]): 指定基础路径。在编译时可能会出现 BasePaths 相关错误可在这里解决。默认为 None 。
            AllowPaths (可选)(Optional[str]): 指定许可路径。在编译时可能会出现 AllowPaths 相关错误可在这里解决。默认为 None 。
            EvmVersion (可选)(Optional[str]): 指定编译时使用的 EVM 版本。默认为 None ，使用当前 solc 支持的最新的 EVM 版本。

        返回值：
            (ABI, Bytecode) (tuple): 由 ABI 和 Bytecode 组成的元组
        """

        try:
            with open(FileCourse, "r", encoding="utf-8") as sol:
                CompiledSol = compile_source(sol.read(), solc_version=SolidityVersion, optimize=Optimize, optimize_runs=OptimizeRuns,
                                             base_path=BasePaths, allow_paths=AllowPaths, evm_version=EvmVersion, output_values=['abi', 'bin'])
            ContractData = CompiledSol[f'<stdin>:{ContractName}']
            ABI, Bytecode = ContractData['abi'], ContractData['bin']
            with open(f'{ContractName}ABI.json', 'w', encoding="utf-8") as f:
                dump(ABI, f, indent=4)
            logger.success(
                f"\n[BlockchainUtils][Compile]\n[FileCourse]{FileCourse}\n[ContractName]{ContractName}\n[ABI]{ABI}\n[Bytecode]{Bytecode}\n{LOG_DIVIDER_LINE}"
            )
            return (ABI, Bytecode)
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][Compile]Failed\n[FileCourse]{FileCourse}\n[ContractName]{ContractName}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            raise Exception("Failed to compile the contract.")

    @staticmethod
    def ImportABI(FileCourse: str) -> str:
        """
        导入指定的 ABI 文件内容。

        参数：
            FileCourse (str): ABI 文件完整路径。当 ABI 文件与脚本文件在同一目录下时可直接使用文件名。

        返回值：
            Result (str): ABI 内容
        """

        with open(FileCourse, 'r', encoding="utf-8") as f:
            return f.read()

    @staticmethod
    def CreateNewAccount() -> tuple:
        """
        创建新账户。

        返回值：
            (Address, PrivateKey) (tuple): 由账户地址和私钥组成的元组
        """

        Temp = EthAccount.create()
        Address, PrivateKey = Web3.to_checksum_address(Temp.address), Temp.key.hex()
        logger.success(f"\n[BlockchainUtils][CreateNewAccount]\n[Address]{Address}\n[PrivateKey]{PrivateKey}\n{LOG_DIVIDER_LINE}")
        return (Address, PrivateKey)

    @staticmethod
    def MnemonicToAddressAndPrivateKey(Mnemonic: str, PassPhrase: str = "", AccountPath: str = "m/44'/60'/0'/0/0") -> tuple:
        """
        将助记词转换为账户地址与私钥。参考 BIP-32 标准。

        参数：
            Mnemonic (str): 助记词字符串。以空格进行分隔。
            PassPhrase (str): 助记词密码。默认为 "" 。
            AccountPath (str): 账户路径。默认为 EVM 地址路径 "m/44'/60'/0'/0/0" 。

        返回值：
            (Address, PrivateKey) (tuple): 由账户地址和私钥组成的元组。当出现异常时返回 None 。
        """

        try:
            EthAccount.enable_unaudited_hdwallet_features()
            Temp = EthAccount.from_mnemonic(Mnemonic, PassPhrase, AccountPath)
            Address, PrivateKey = Web3.to_checksum_address(Temp.address), Temp.key.hex()
            logger.success(
                f"\n[BlockchainUtils][MnemonicToAddressAndPrivateKey]\n[Mnemonic]{Mnemonic}\n[PassPhrase]{PassPhrase if PassPhrase else None}\n[AccountPath]{AccountPath}\n[Address]{Address}\n[PrivateKey]{PrivateKey}\n{LOG_DIVIDER_LINE}"
            )
            return (Address, PrivateKey)
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][MnemonicToAddressAndPrivateKey]Failed\n[Mnemonic]{Mnemonic}\n[PassPhrase]{PassPhrase if PassPhrase else None}\n[AccountPath]{AccountPath}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
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
            assert (Value > 0)
            return int(Value * 10**9)
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][GweiToWei]Failed\n[Value]{Value}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def WeiToGwei(Value: int) -> float:
        """
        将一个正整数按照 wei 为单位直接转化为 Gwei 为单位的正整数。即假设传入 Value = 1000000000，将返回 1 。

        参数：
            Value (int): 假设以 wei 为单位的待转换值。

        返回值：
            Result (float): 已转换为以 Gwei 为单位的值。当出现异常时返回 None 。
        """

        try:
            assert (Value > 0)
            return float(Value / 10**9)
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][WeiToGwei]Failed\n[Value]{Value}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def FromWei(Number: int, Unit: str) -> Union[int, Decimal]:
        """
        Web3.from_wei 的简单封装。

        参数：
            Number (int): 待转换值。
            Unit (str): 原单位名称。

        返回值：
            Result (Union[int, Decimal]): 转换后的值。
        """

        return Web3.from_wei(Number, Unit)

    @staticmethod
    def ToWei(Number: Union[int, float, str, Decimal], Unit: str) -> int:
        """
        Web3.to_wei 的简单封装。

        参数：
            Number (Union[int, float, str, Decimal]): 待转换值。
            Unit (str): 原单位名称。

        返回值：
            Result (int): 转换后的值。
        """

        return Web3.to_wei(Number, Unit)

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
            Bytecode = assemble_hex(Assembly)
            logger.success(f"\n[BlockchainUtils][AssemblyToBytecode]\n[Bytecode]{Bytecode}\n{LOG_DIVIDER_LINE}")
            return Bytecode
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][AssemblyToBytecod]Failed\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
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
            Assembly = disassemble_hex(Bytecode)
            logger.success(f"\n[BlockchainUtils][AssemblyToBytecode]\n[Assembly]\n{Assembly}\n{LOG_DIVIDER_LINE}")
            return Assembly
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][BytecodeToAssembly]Failed\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def SignatureToRSV(Signature: str) -> SignatureData:
        """
        将签名解析成 R S V 。

        参数：
            Signature (str): 签名。含 0x 前缀的十六进制形式。

        返回值：
            Result (SignatureData): 解析结果。当出现异常时返回 None 。
            {"Signature"|"R"|"S"|"V"}
        """

        try:
            Signature = hex(int(Signature, 16))
            assert (len(Signature) == 130 + 2)
            R, S, V = '0x' + Signature[2:66], '0x' + Signature[66:-2], '0x' + Signature[-2:]
            logger.success(f"\n[BlockchainUtils][SignatureToRSV]\n[Signature]{Signature}\n[R]{R}\n[S]{S}\n[V]{V}\n{LOG_DIVIDER_LINE}")
            Result: SignatureData = SignatureData(**{
                "Signature": Signature,
                "R": R,
                "S": S,
                "V": V
            })
            return Result
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][SignatureToRSV]Failed\n[Signature]{Signature}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def RSVToSignature(R: str, S: str, V: str) -> SignatureData:
        """
        将 R S V 合并成签名。

        参数：
            R (str): 签名 r 值。含 0x 前缀的十六进制形式。
            S (str): 签名 s 值。含 0x 前缀的十六进制形式。
            V (int): 签名 v 值。含 0x 前缀的十六进制形式。

        返回值：
            Result (SignatureData): 合并结果。当出现异常时返回 None 。
            {"Signature"|"R"|"S"|"V"}
        """

        try:
            R, S, V = hex(int(R, 16)), hex(int(S, 16)), hex(int(V, 16))
            assert (len(R) == 64 + 2 and len(S) == 64 + 2 and len(V) == 2 + 2)
            Signature = '0x' + R[2:] + S[2:] + V[2:]
            logger.success(f"\n[BlockchainUtils][RSVToSignature]\n[R]{R}\n[S]{S}\n[V]{V}\n[Signature]{Signature}\n{LOG_DIVIDER_LINE}")
            Result: SignatureData = SignatureData(**{
                "Signature": Signature,
                "R": R,
                "S": S,
                "V": V
            })
            return Result
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][RSVToSignature]Failed\n[R]{R}\n[S]{S}\n[V]{V}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
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
            logger.success(f"\n[BlockchainUtils][GetFunctionSelector]\n[FunctionName]{FunctionName}\n[FunctionParameters]{FunctionParameters}\n[FunctionSelector]{FunctionSelector}\n{LOG_DIVIDER_LINE}")
            return FunctionSelector
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][GetFunctionSelector]Failed\n[FunctionName]{FunctionName}\n[FunctionParameters]{FunctionParameters}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
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
            Signer = EthAccount.recover_message(encode_defunct(text=Message), signature=Signature)
            logger.success(f"\n[BlockchainUtils][RecoverMessage]\n[Message]{Message}\n[Signature]{Signature}\n[Signer]{Signer}\n{LOG_DIVIDER_LINE}")
            return Signer
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][RecoverMessage]Failed\n[Message]{Message}\n[Signature]{Signature}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
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
            Signer = EthAccount._recover_hash(MessageHash, signature=Signature)
            logger.success(
                f"\n[BlockchainUtils][RecoverMessageByHash]\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[Signer]{Signer}\n{LOG_DIVIDER_LINE}"
            )
            return Signer
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][RecoverMessageByHash]Failed\n[MessageHash]{MessageHash}\n[Signature]{Signature}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def GetContractAddressByCREATE(Deployer: str, Nonce: int) -> str:
        """
        获取某账户以 CREATE 方式部署的合约的地址。

        参数：
            Deployer (str): 部署者地址
            Nonce (int): 部署者发送合约部署交易的 nonce 值

        返回值：
            Address (str): 计算出的合约地址
        """

        try:
            Address = utils.address.get_create_address(Deployer, Nonce)
            logger.success(
                f"\n[BlockchainUtils][GetContractAddressByCREATE]\n[Deployer]{Deployer}\n[Nonce]{Nonce}\n[ContractAddress]{Address}\n{LOG_DIVIDER_LINE}"
            )
            return Address
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][GetContractAddressByCREATE]Failed\n[Deployer]{Deployer}\n[Nonce]{Nonce}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None

    @staticmethod
    def GetContractAddressByCREATE2(Deployer: str, Salt: str, CreationCode: str) -> str:
        """
        获取某合约账户以 CREATE2 方式部署的另一个合约的地址。

        参数：
            Deployer (str): 部署者地址
            Salt (str): 盐值
            CreationCode (str): 合约的创建时字节码

        返回值：
            Address (str): 计算出的合约地址
        """

        try:
            Address = utils.address.get_create2_address(Deployer, Salt, CreationCode)
            logger.success(
                f"\n[BlockchainUtils][GetContractAddressByCREATE2]\n[Deployer]{Deployer}\n[Salt]{Salt}\n[CreationCode]{CreationCode}\n[ContractAddress]{Address}\n{LOG_DIVIDER_LINE}"
            )
            return Address
        except Exception:
            ExceptionInformation = format_exc()
            logger.error(
                f"\n[BlockchainUtils][GetContractAddressByCREATE2]Failed\n[Deployer]{Deployer}\n[Salt]{Salt}\n[CreationCode]{CreationCode}\n[ExceptionInformation]{ExceptionInformation}{LOG_DIVIDER_LINE}"
            )
            return None
