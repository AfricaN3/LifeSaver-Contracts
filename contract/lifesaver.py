from typing import Union
from boa3.builtin import CreateNewEvent, NeoMetadata, metadata, public
from boa3.builtin.interop.storage import get
from boa3.builtin.type import UInt160

# -------------------------------------------
# METADATA
# -------------------------------------------


@metadata
def manifest_metadata() -> NeoMetadata:
    """
    Defines this smart contract's metadata information
    """
    meta = NeoMetadata()
    meta.author = 'AfricaN3'
    meta.description = 'The NFTs for Life Savers (to be changed)'
    meta.email = 'hello@african3.com'
    meta.supported_standards = ['NEP-11']
    return meta


# -------------------------------------------
# TOKEN SETTINGS
# -------------------------------------------

# Symbol of the Token
TOKEN_SYMBOL = 'LIFE'

# Number of decimal places
TOKEN_DECIMALS = 0

# -------------------------------------------
# Keys
# -------------------------------------------

# Stores the total token count
TOKEN_COUNT: bytes = b'!TOKEN_COUNT'

# Epoch count
EPOCH_COUNT: bytes = b'EPOCH_COUNT'

# Stores the total account count
ACCOUNT_COUNT: bytes = b'!ACCOUNT_COUNT'

# -------------------------------------------
# Events
# -------------------------------------------

on_transfer = CreateNewEvent(
    # trigger when tokens are transferred, including zero value transfers.
    [
        ('from_addr', Union[UInt160, None]),
        ('to_addr', Union[UInt160, None]),
        ('amount', int),
        ('token_id', bytes)
    ],
    'Transfer'
)

# -------------------------------------------
# NEP-11 Methods
# -------------------------------------------

@public
def symbol() -> str:
    """
    Gets the symbols of the token.

    :return: a short string representing symbol of the token managed in this contract.
    """
    return TOKEN_SYMBOL


@public
def decimals() -> int:
    """
    Gets the amount of decimals used by the token.

    E.g. 8, means to divide the token amount by 100,000,000 (10 ^ 8) to get its user representation.
    This method must always return the same value every time it is invoked.

    :return: the number of decimals used by the token.
    """
    return TOKEN_DECIMALS


@public
def totalSupply() -> int:
    """
    Gets the total token supply deployed in the system.

    This number must not be in its user representation. E.g. if the total supply is 10,000,000 tokens, this method
    must return 10,000,000 * 10 ^ decimals.

    :return: the total token supply deployed in the system.
    """
    total: bytes = get(TOKEN_COUNT)
    if len(total) == 0:
        return 0
    return total.to_int()


