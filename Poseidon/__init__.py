from importlib.metadata import version

__version__ = version("poseidon-python")

from Poseidon.EVM import (Chain, Account, Contract, Utils)

__all__ = [
    "__version__",
    "Chain",
    "Account",
    "Contract",
    "Utils",
]
