from importlib.metadata import version

__version__ = version("poseidon-python")

from poseidon import evm, ton, solana, sui

__all__ = [
    "__version__",
    "evm",
    "ton",
    "solana",
    "sui"
]
