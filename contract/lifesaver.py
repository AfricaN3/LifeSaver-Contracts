from typing import Any, Dict, List, Union, cast
from boa3.builtin import contract, CreateNewEvent, NeoMetadata, metadata, public
from boa3.builtin.contract import abort
from boa3.builtin.interop.blockchain import get_contract, Transaction
from boa3.builtin.interop.contract import call_contract, update_contract, GAS
from boa3.builtin.interop.runtime import time, check_witness, script_container, calling_script_hash, executing_script_hash, get_random
from boa3.builtin.interop.stdlib import serialize, deserialize, itoa, base64_encode, base64_decode
from boa3.builtin.interop.storage import delete, get, put, find, get_context, get_read_only_context
from boa3.builtin.interop.storage.findoptions import FindOptions
from boa3.builtin.interop.iterator import Iterator
from boa3.builtin.type import UInt160, ByteString

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

ERA_FEE_KEY: bytes = b'ERA_FEE'
# Initial fee = 100 GAS
INITIAL_ERA_FEE = 10_000_000_000

# Era count
ERA_COUNT: bytes = b'ERA_COUNT'

# The presence of an era for a wallet
ERA_PRESENCE = 'ep/'

# Stores the total account count
ACCOUNT_COUNT: bytes = b'!ACCOUNT_COUNT'

# Actions
ACTION_DONATE = 'ACTION_DONATE'
ACTION_CREATE_ERA = 'ACTION_CREATE_ERA'

# -------------------------------------------
# Events
# -------------------------------------------

on_transfer = CreateNewEvent(
    # trigger when tokens are transferred, including zero value transfers.
    [
        ('from_addr', Union[UInt160, None]),
        ('to_addr', Union[UInt160, None]),
        ('amount', int),
        ('token_id', ByteString)
    ],
    'Transfer'
)

on_donation_deposit = CreateNewEvent(
    [
        ('account', UInt160),
        ('donation_quantity', int),
        ('era', bytes)
    ],
    'DonationDeposit'
)

on_era_created = CreateNewEvent(
    [
        ('era', int),
        ('organization', bytes)
    ],
    'EraCreated'
)

# -------------------------------------------
# contract Methods
# -------------------------------------------

def validate_address(address: UInt160) -> bool:
    if not isinstance(address, UInt160):
        return False
    if address == 0:
        return False
    return True

@public(safe=True)
def getEraFee() -> int:
    return get(ERA_FEE_KEY).to_int()


@public
def setEraFee(era_fee: int) -> bool:
    assert era_fee >= 0, 'era_fee must be a non-negative integer'
    tx = cast(Transaction, script_container)
    user: User = get_user(tx.sender)
    assert user.get_contract_upgrade(), 'User Permission Denied'
    put(ERA_FEE_KEY, era_fee)
    return True

# -------------------------------------------
# NEP-11 Methods
# -------------------------------------------

@public(safe=True)
def symbol() -> str:
    """
    Gets the symbols of the token.

    :return: a short string representing symbol of the token managed in this contract.
    """
    return TOKEN_SYMBOL


@public(safe=True)
def decimals() -> int:
    """
    Gets the amount of decimals used by the token.

    E.g. 8, means to divide the token amount by 100,000,000 (10 ^ 8) to get its user representation.
    This method must always return the same value every time it is invoked.

    :return: the number of decimals used by the token.
    """
    return TOKEN_DECIMALS


@public(safe=True)
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


@public(safe=True)
def balanceOf(owner: UInt160) -> int:
    """
    Get the current balance of an address

    The parameter owner must be a 20-byte address represented by a UInt160.

    :param owner: the owner address to retrieve the balance for
    :type owner: UInt160
    :return: the total amount of tokens owned by the specified address.
    :raise AssertionError: raised if `owner` length is not 20.
    """
    assert len(owner) == 20, 'Incorrect `owner` length'
    user: User = get_user(owner)
    return user.get_balance_of()


@public(safe=True)
def tokensOf(owner: UInt160) -> Iterator:
    """
    Get all of the token ids owned by the specified address

    The parameter owner must be a 20-byte address represented by a UInt160.

    :param owner: the owner address to retrieve the tokens for
    :type owner: UInt160
    :return: an iterator that contains all of the token ids owned by the specified address.
    :raise AssertionError: raised if `owner` length is not 20.
    """
    assert len(owner) == 20, 'Incorrect `owner` length'
    user: User = get_user(owner)
    return user.get_owned_tokens()


@public
def transfer(to: UInt160, token_id: ByteString, data: Any) -> bool:
    """
    Transfers the token with id token_id to address to

    The parameter to SHOULD be a 20-byte address. If not, this method SHOULD throw an exception. The parameter 
    token_id SHOULD be a valid NFT. If not, this method SHOULD throw an exception. If the method succeeds, 
    it MUST fire the Transfer event, and MUST return true, even if the token is sent to the owner. If the receiver is 
    a deployed contract, the function MUST call onNEP11Payment method on receiver contract with the data parameter 
    from transfer AFTER firing the Transfer event. 

    The function SHOULD check whether the owner address equals the caller contract hash. If so, the transfer SHOULD be
    processed; If not, the function SHOULD use the SYSCALL Neo.Runtime.CheckWitness to verify the transfer.

    If the transfer is not processed, the function SHOULD return false.

    :param to: the address to transfer to 
    :type to: UInt160 
    :param token_id: the token to transfer 
    :type token_id: ByteString 
    :param data: whatever data is pertinent to the onPayment method 
    :type data: Any 
    :return: whether the transfer was successful 
    :raise AssertionError: raised if `to` length is not 20 or if `token_id` is not a valid 
    NFT
    """
    assert len(to) == 20, 'Incorrect `to` length'

    token_id_bytes: bytes = token_id.to_bytes()
    life: Life = get_life(token_id_bytes)
    token_owner: UInt160 = life.get_owner()
    life_era_id: bytes = life.get_era_id()

    assert life.is_transferable(), 'Life cannot be transferred, contact era admin for help'
    assert not isOfEra(to, life_era_id), 'There is LIFE belonging to this era in this account already'

    formatted_token_id: bytes = life.get_token_id()
    if not check_witness(token_owner):
        return False

    owner_user: User = get_user(token_owner)
    to_user: User = get_user(to)

    if token_owner != to:

        removeEraFromAccount(token_owner, life_era_id)
        addEraToAccount(to, life_era_id)

        owner_user.remove_owned_token(formatted_token_id)
        to_user.add_owned_token(formatted_token_id)

        save_user(token_owner, owner_user)
        save_user(to, to_user)

        life.set_owner(to)
        save_life(life)

    post_transfer(token_owner, to, token_id_bytes, data)
    return True


def post_transfer(token_owner: Union[UInt160, None], to: Union[UInt160, None], token_id: bytes, data: Any):
    """
    Checks if the one receiving NEP11 tokens is a smart contract and if it's one the onPayment method will be called 
    - internal 

    :param token_owner: the address of the sender
    :type token_owner: UInt160
    :param to: the address of the receiver
    :type to: UInt160
    :param token_id: the token hash as bytes
    :type token_id: bytes
    :param data: any pertinent data that might validate the transaction
    :type data: Any
    """
    on_transfer(token_owner, to, 1, token_id)
    if not isinstance(to, None):  # TODO: change to 'is not None' when `is` semantic is implemented
        recipient_contract = get_contract(to)
        if not isinstance(recipient_contract, None):  # TODO: change to 'is not None' when `is` semantic is implemented
            call_contract(to, 'onNEP11Payment', [token_owner, 1, token_id, data])
            pass


@public(safe=True)
def ownerOf(token_id: ByteString) -> UInt160:
    """
    Get the owner of the specified token.

    The parameter token_id SHOULD be a valid NFT. If not, this method SHOULD throw an exception.

    :param token_id: the token for which to check the ownership
    :type token_id: ByteString
    :return: the owner of the specified token.
    :raise AssertionError: raised if `token_id` is not a valid NFT.
    """
    token_id_bytes: bytes = token_id.to_bytes()
    life: Life = get_life(token_id_bytes)
    owner = life.get_owner()
    return owner


@public(safe=True)
def tokens() -> Iterator:
    """
    Get all tokens minted by the contract

    :return: an iterator that contains all of the tokens minted by the contract.
    """
    flags = FindOptions.REMOVE_PREFIX
    context = get_context()
    return find(TOKEN_PREFIX, context, flags)


@public(safe=True)
def properties(token_id: ByteString) -> Dict[str, Any]:
    """
    Get the properties of a token.

    The parameter token_id SHOULD be a valid NFT. If no metadata is found (invalid token_id), an exception is thrown.

    :param token_id: the token for which to check the properties
    :type token_id: ByteString
    :return: a serialized NVM object containing the properties for the given NFT.
    :raise AssertionError: raised if `token_id` is not a valid NFT, or if no metadata available.
    """
    token_id_bytes: bytes = token_id.to_bytes()
    life_json = get_life_json_flat(token_id_bytes)
    assert len(life_json) != 0, 'life does not exist'

    return life_json


@public
def _deploy(data: Any, update: bool):
    """
    Executes the deploy event by creating the initial contract state and admin account
    :param owner: The initial admin of of the smart contract
    :return: a boolean indicating success
    """

    if not update:
        put(TOKEN_COUNT, 0)
        put(ACCOUNT_COUNT, 1)
        put(ERA_FEE_KEY, INITIAL_ERA_FEE)

        super_user_permissions: Dict[str, bool] = {
            'offline_mint': True,
            'contract_upgrade': True,
            'manage_era': True,
            'initiate_transfer': True,
            'set_permissions': True
        }

        tx = cast(Transaction, script_container)
        owner: UInt160 = tx.sender

        user: User = User()
        user.set_permissions(super_user_permissions)
        save_user(owner, user)


@public
def onNEP11Payment(from_address: UInt160, amount: int, token_id: bytes, data: Any):
    """
    :param from_address: the address of the one who is trying to send cryptocurrency to this smart contract
    :type from_address: UInt160
    :param amount: the amount of cryptocurrency that is being sent to the this smart contract
    :type amount: int
    :param token_id: the token hash as bytes
    :type token_id: bytes
    :param data: any pertinent data that might validate the transaction
    :type data: Any
    """
    abort()


@public
def onNEP17Payment(from_address: UInt160, amount: int, data: Any):
    """
    :param from_address: the address of the one who is trying to send cryptocurrency to this smart contract
    :type from_address: UInt160
    :param amount: the amount of cryptocurrency that is being sent to the this smart contract
    :type amount: int
    :param data: any pertinent data that might validate the transaction
    create_era(organization: bytes, date: bytes, no_of_winners: int)
    :type data = [ action_type: bytes, winners_no || era_id: int, organization: bytes, date: bytes, mint_fee: bytes ]
    :raise AssertionError: raised if `from_address` length is not 20
    """
    assert amount >= 0, 'amount must be non-negative'
     # the parameters from and to should be 20-byte addresses. If not, this method should throw an exception.
    if from_address is not None:
        assert validate_address(from_address), 'from_address must be a valid 20 byte UInt160'

    # this validation will verify if Neo is trying to mint GAS to this smart contract and should add to AfricaN3 pool
    if from_address is None and calling_script_hash == GAS:
        return

    transfer_data = cast(list, data)
    action_type = cast(str, transfer_data[0])

    if action_type == ACTION_DONATE:
        if calling_script_hash != GAS:
            abort()
        era_id: bytes = cast(bytes, transfer_data[1])
        donate_to_era(era_id, amount, from_address)   
    elif action_type == ACTION_CREATE_ERA:
        if calling_script_hash != GAS:
            abort()
        assert amount == getEraFee(), 'amount is invalid for era creation'
        no_of_winners = cast(int, transfer_data[1])
        organization = cast(bytes, transfer_data[2])
        date = cast(bytes, transfer_data[3])
        mint_fee = cast(int, transfer_data[4])
        create_era(organization, date, no_of_winners, mint_fee)
    else:
        abort()
        


# -------------------------------------------
# Methods
# -------------------------------------------


@public(safe=True)
def total_accounts() -> int:
    """
    Gets the number of accounts.

    :return: the number of accounts in the system.
    """
    total: bytes = get(ACCOUNT_COUNT)
    if len(total) == 0:
        return 0
    return total.to_int()


@public
def offline_mint(era_id: bytes, account: UInt160) -> bytes:
    """
    mints a token from an era
    :param account: the account to mint to
    :return: the token_id of the minted token
    :raise AssertionError: raised if the signer does not have `offline_mint` permission.
    """
    tx = cast(Transaction, script_container)
    user: User = get_user(tx.sender)
    mint_era: Era = get_era(era_id)
    is_era_admin: bool = mint_era.get_admin() == tx.sender
    can_mint_offline: bool = user.get_offline_mint() 
    can_mint: bool = can_mint_offline or is_era_admin

    assert can_mint, 'User Permission Denied'
    return internal_mint(era_id, account)


@public
def update(script: bytes, manifest: bytes, data: Any):
    """
    Upgrade the contract.

    :param script: the contract script
    :type script: bytes
    :param manifest: the contract manifest
    :type manifest: bytes
    :raise AssertionError: raised if the signer does not have the 'update' permission
    """
    tx = cast(Transaction, script_container)
    user: User = get_user(tx.sender)
    assert user.get_contract_upgrade(), 'User Permission Denied'

    update_contract(script, manifest, data)


def internal_mint(era_id: bytes, owner: UInt160) -> bytes:
    """
    Mint new token - internal

    :param era_id: the era id to mint from
    :param owner: the address of the account that is minting token
    :type owner: UInt160
    :return: token_id of the token minted
    """

    mint_era: Era = get_era(era_id)
    assert mint_era.can_mint(), 'No available LIFE to mint in the selected era'

    assert not isOfEra(owner, era_id), 'There is LIFE belonging to this era in this account already'
    addEraToAccount(owner, era_id)

    mint_era.increment_supply()
    save_era(mint_era)

    token_id_int: int = (totalSupply() + 1)
    token_id_string: bytes = itoa(token_id_int)
    new_life: Life = Life()
    new_life.generate(owner, token_id_string, era_id)

    save_life(new_life)
    put(TOKEN_COUNT, token_id_int)

    user: User = get_user(owner)
    user.add_owned_token(token_id_string)
    save_user(owner, user)

    post_transfer(None, owner, token_id_string, None)

    return token_id_string


# #############################
# ########### User ############
# #############################


ACCOUNT_PREFIX = b'a'
TOKEN_INDEX_PREFIX = b'i'


class User:

    def __init__(self):
        self._balance: int = 0
        self._permissions: Dict[str, bool] = {
            'offline_mint': False,
            'contract_upgrade': False,
            'manage_era': False,
            'initiate_transfer': False,
            'set_permissions': False
        }

        self._account_id: bytes = (total_accounts() + 1).to_bytes()

    def export(self) -> Dict[str, Any]:
        exported: Dict[str, Any] = {
            'balance': self._balance,
            'account_id': self._account_id,
            'permissions': self._permissions
        }
        return exported

    def set_permissions(self, permissions: Dict[str, bool]) -> bool:
        perm_clone = self._permissions
        for key in permissions.keys():
            perm_clone[key] = permissions[key]
        self._permissions = perm_clone
        return True

    def get_account_id(self) -> bytes:
        return self._account_id

    def get_balance_of(self) -> int:
        return self._balance

    def get_owned_tokens(self) -> Iterator:
        return find(mk_token_index_key(self._account_id))

    def add_owned_token(self, token_id: bytes) -> bool:
        key: bytes = mk_token_index_key(self._account_id) + token_id
        self._balance = self._balance + 1
        put(key, token_id)
        return True

    def remove_owned_token(self, token_id: bytes) -> bool:
        key: bytes = mk_token_index_key(self._account_id) + token_id
        self._balance = self._balance - 1
        delete(key)
        return True

    def get_offline_mint(self) -> bool:
        return self._permissions['offline_mint']

    def get_set_permissions(self) -> bool:
        return self._permissions['set_permissions']

    def can_manage_era(self) -> bool:
        return self._permissions['manage_era']

    def can_initiate_transfer(self) -> bool:
        return self._permissions['initiate_transfer']

    def get_contract_upgrade(self) -> bool:
        return self._permissions['contract_upgrade']


@public(safe=True)
def get_user_json(address: UInt160) -> Dict[str, Any]:
    """
    Gets the JSON representation of a user account
    :param address: The address being requested
    :return: A Dict representing the user
    """
    user: User = get_user(address)
    return user.export()

@public(safe=True)
def get_user(address: UInt160) -> User:
    """
    Gets a User instance
    :param address: The address being requested
    :return: The User instance for the requested address
    """
    user_bytes: bytes = get_user_raw(address)
    if len(user_bytes) != 0:
        return cast(User, deserialize(user_bytes))

    return User()


def get_user_raw(address: UInt160) -> bytes:
    return get(mk_user_key(address))


def save_user(address: UInt160, user: User) -> bool:
    """
    Saves a user instance
    :param address: The address to save the user against
    :param user: the User instance being saved
    :return: A bool indicating completion
    """
    account_id: bytes = user.get_account_id()
    account_count: int = total_accounts()
    if account_id.to_int() > account_count:
        put(ACCOUNT_COUNT, account_id)

    put(mk_user_key(address), serialize(user))
    return True


def mk_user_key(address: UInt160) -> bytes:
    return ACCOUNT_PREFIX + address


def mk_token_index_key(account_id: bytes) -> bytes:
    return TOKEN_INDEX_PREFIX + account_id + b'_'


@public(safe=True)
def isOfEra(account: UInt160, era_id: bytes) -> bool:
    assert validate_address(account), 'address must be a valid 20 byte UInt160'
    era_id_string = base64_encode(era_id)
    account64 = base64_encode(account)
    return get_read_only_context().create_map(ERA_PRESENCE + era_id_string + '/').get(account64).to_bool()


def addEraToAccount(account: UInt160, era_id: bytes) -> bool:
    era_id_string = base64_encode(era_id)
    account64 = base64_encode(account)
    get_context().create_map(ERA_PRESENCE + era_id_string + '/').put(account64, True)
    return True


def removeEraFromAccount(account: UInt160, era_id: bytes) -> bool:
    era_id_string = base64_encode(era_id)
    account64 = base64_encode(account)
    get_context().create_map(ERA_PRESENCE + era_id_string + '/').delete(account64)
    return True

@public
def set_user_permissions(user: UInt160, permissions: Dict[str, bool]) -> bool:
    """
    Sets a user's permissions
    :param user: The address of the user to edit
    :param permissions: A dictionary representing the permissions to update
    :return: a boolean indicating success
    """
    tx = cast(Transaction, script_container)
    invoking_user: User = get_user(tx.sender)
    assert invoking_user.get_set_permissions(), 'User Permission Denied'

    impacted_user: User = get_user(user)
    impacted_user.set_permissions(permissions)
    save_user(user, impacted_user)
    return True


# #############################
# ########## Era ############
# #############################
# #############################


ERA_PREFIX = b'e'


class Era:
    def __init__(self, admin: UInt160, organization: bytes, date: bytes, no_of_winners: int, mint_fee: int):
        self._admin: UInt160 = admin
        self._organization: bytes = organization
        self._date: bytes = date
        self._no_of_winners: int = no_of_winners
        self._mint_fee: int = mint_fee
        self._era_id: bytes = (total_era() + 1).to_bytes()
        self._total_supply: int = 0
        self._reward: int = getEraFee()
        self._status: int = 0

    def can_mint(self) -> bool:
        return self._status == 0

    def can_donate(self) -> bool:
        return self._status <= 1

    def can_pay_winners(self) -> bool:
        return self._status == 1

    def get_id(self) -> bytes:
        return self._era_id

    def get_admin(self) -> UInt160:
        return self._admin

    def get_organization(self) -> bytes:
        return self._organization

    def get_date(self) -> bytes:
        return self._date

    def get_no_of_winners(self) -> int:
        return self._no_of_winners

    def get_mint_fee(self) -> int:
        return self._mint_fee

    def get_status(self) -> int:
        """
        Getter for the status of the era
        @return: integer range(0-2) representing the stage of the era
        0 = created state of era, funds can be donated to the era
        1 = blood drive event has ended, LIFE can no longer be minted to the era
        2 = era rewards completely paid, funds can no longer donated to the era
        """
        return self._status

    def get_reward(self) -> int:
        return self._reward

    def get_total_supply(self) -> int:
        return self._total_supply

    def export(self) -> Dict[str, Any]:
        exported: Dict[str, Any] = {
            'admin': self._admin,
            'organization': self._organization,
            'date': self._date,
            'eraId': self._era_id,
            'winnersNumber': self._no_of_winners,
            'status': self.get_status(),
            'reward': self.get_reward(),
            'mintFee': self.get_mint_fee(),
            'totalSupply': self.get_total_supply()
        }
        return exported

    def increment_supply(self) -> int:
        self._total_supply = self._total_supply + 1
        return self._total_supply

    def increment_reward(self, amount: int) -> int:
        self._reward = self._reward + amount
        return self._reward

    def increment_status(self) -> bool:
        self._status = self._status + 1
        return True


def create_era(organization: bytes, date: bytes, no_of_winners: int, mint_fee: int) -> int:
    tx = cast(Transaction, script_container)
    admin: UInt160 = tx.sender

    new_era: Era = Era(admin, organization, date, no_of_winners, mint_fee)
    era_id: bytes = new_era.get_id()
    era_id_int: int = era_id.to_int()

    save_era(new_era)
    put(ERA_COUNT, era_id)
    on_era_created(era_id_int, organization)
    return era_id_int


@public(safe=True)
def get_era_json(era_id: bytes) -> Dict[str, Any]:
    era: Era = get_era(era_id)
    return era.export()


@public(safe=True)
def get_era(era_id: bytes) -> Era:
    era_bytes: bytes = get_era_raw(era_id)
    return cast(Era, deserialize(era_bytes))


def get_era_raw(era_id: bytes) -> bytes:
    return get(mk_era_key(era_id))


@public(safe=True)
def total_era() -> int:
    """
    Gets the total epoch count.  No

    Epoch id is an incrementor so users can iterator from 1 - total_era() to dump every epoch on the contract.

    :return: the total token epochs deployed in the system.
    """
    total: bytes = get(ERA_COUNT)
    if len(total) == 0:
        return 0
    return total.to_int()


@public
def end_era(era_id: bytes) -> bool:
    """
    Ends an era.

    This method ends minting NFTs to the era (changes the status to 1) and also creates a 
    collection of era NFT holders on the Collection contract.

    :return: a boolean indicating success
    """
    era_to_end: Era = get_era(era_id)
    tx = cast(Transaction, script_container)
    user: User = get_user(tx.sender)
    is_era_admin: bool = era_to_end.get_admin() == tx.sender
    can_manage_era: bool = user.can_manage_era()
    can_end_era: bool = can_manage_era or is_era_admin

    assert era_to_end.can_mint(), 'Era is already ended'
    assert can_end_era, 'User Permission Denied'
    assert era_to_end.get_total_supply() >= era_to_end.get_no_of_winners(), 'Not enough era NFT owners to end era'
    
    era_to_end.increment_status()
    save_era(era_to_end)

    return True


@public
def pay_winners(era_id: bytes) -> bool:
    """
    Carries out a raffle to reward NFT holders of a particular era.

    This method randomly select winners for an era and also creates 
    a collection of the winning addresses on the Collection contract

    :return: a boolean indicating success
    """
    era_to_pay: Era = get_era(era_id)
    reward_pool : int = era_to_pay.get_reward()
    number_of_winners: int = era_to_pay.get_no_of_winners()
    tx = cast(Transaction, script_container)

    user: User = get_user(tx.sender)
    is_era_admin: bool = era_to_pay.get_admin() == tx.sender
    can_manage_era: bool = user.can_manage_era()
    is_authorized: bool = can_manage_era or is_era_admin

    assert era_to_pay.can_pay_winners(), 'Inappropriate Era status'
    assert is_authorized, 'User Permission Denied'

    era_to_pay.increment_status()
    save_era(era_to_pay)

    holders = createListOfEraAccounts(era_id)
    
    for x in range(number_of_winners):
        idx: int = rand_between_internal(0, len(holders) - 1)
        winner: UInt160 = holders[idx]
        amount_payable = reward_pool // number_of_winners
        call_contract(GAS, 'transfer',
                    [executing_script_hash, winner, amount_payable, None])
    

    return True


def rand_between_internal(start: int, end: int) -> int:
    """
    Samples from a random data stream and returns a uniform random integer between start and end inclusively.
    This method support both positive and negative starting and ending values so long as start < end.
    :param start: the starting integer
    :param end: the ending integer
    :return: a random integer of range start-end
    """
    raw_entropy: bytes = get_random().to_bytes()
    entropy: bytes = raw_entropy[0:8]
    max_entropy: int = 2 ** (len(entropy) * 8)
    half_max_entropy: int = (max_entropy // 2)
    entropy_int: int = entropy.to_int()
    u_entropy_int: int = entropy_int + half_max_entropy

    numerator: int = ((end + 1) - start) * u_entropy_int

    return (numerator // max_entropy) + start


def save_era(era: Era) -> bool:
    era_id: bytes = era.get_id()
    put(mk_era_key(era_id), serialize(era))
    return True


def mk_era_key(era_id: bytes) -> bytes:
    return ERA_PREFIX + era_id

def donate_to_era(era_id: bytes, amount: int, donor: UInt160) -> bool:
    """
    Make donation to an Era - internal

    :param era_id: the era id to donate to
    :param amount: the amount of GAS donated
    :param donor: the address of the account that donated
    :type owner: UInt160
    :return: bool to know if donation was successful
    """
    era_donated: Era = get_era(era_id)
    assert era_donated.can_donate(), 'Donating to this Era is not allowed'
    era_donated.increment_reward(amount)
    save_era(era_donated)
    if amount == era_donated.get_mint_fee():
        internal_mint(era_id, donor)
    on_donation_deposit(donor, amount, era_id)
    return True


# Gets the accounts that belong to an era into a list
def createListOfEraAccounts(era_id: bytes) -> List[UInt160]:
    era_id_string = base64_encode(era_id)
    era_accounts_key = ERA_PRESENCE + era_id_string + '/'
    accounts = find(era_accounts_key)

    accounts_list: List[UInt160] = []
    while accounts.next():
        account64 = cast(str, accounts.value[0])[len(era_accounts_key):]
        account = UInt160(base64_decode(account64))
        accounts_list.append(account)

    return accounts_list  


# #############################
# ########## Life ###########
# #############################
# #############################


TOKEN_PREFIX = b't'


class Life:

    def __init__(self):
        self._token_id: bytes = b''
        self._era_token_id: int = 0
        self._timestamp: int = 0
        self._era_id: bytes = b''
        self._owner: UInt160 = UInt160()

    def export(self) -> Dict[str, Any]:
        exported: Dict[str, Any] = {
            'owner': self._owner,
            'tokenId': self._token_id,
            'eraId': self._era_id,
            'eraTokenId': self._era_token_id
        }
        return exported

    def generate(self, owner: UInt160, token_id: bytes, era_id: bytes) -> bool:
        """
        Generates a Life's core features
        @return: boolean indicating success
        """
        # generate base attributes
        target_era: Era = get_era(era_id)
        self._timestamp = time

        # mint traits
        self._era_id = era_id

        # Generate a life token_id and set the owner
        self._owner = owner
        self._token_id = token_id
        self._era_token_id = target_era.get_total_supply()

        return True

    def get_owner(self) -> UInt160:
        """
        Getter for the Life owner
        @return: bytes representing the owner of the Life
        """
        return UInt160(self._owner)
        
    def get_era_id(self) -> bytes:
        """
        Getter for the Life era ID
        @return: bytes representing the era ID of the Life
        """
        return self._era_id

    def is_transferable(self) -> bool:
        """
        Getter for the Life mobiity
        @return: Boolean indicating if life is transferrable
        """
        return self._timestamp >= time

    def get_state(self) -> Dict[str, Any]:
        """
        Gets the state of the life. This differs from an export in that it includes all secondary features like
         timestamp.
        @return:
        """
        token_id_bytes: bytes = self._token_id
        era_id_bytes: bytes = self._era_id

        era_id_int: int = era_id_bytes.to_int()
        era: Era = get_era(era_id_bytes)
        era_organization: bytes = era.get_organization()

        exported: Dict[str, Any] = {
            'description': 'LifeSaver NFT #' + token_id_bytes.to_str() + '. This is a Soulbound token minted during ' + 
                            'a blood drive event ' + '(' + itoa(era_id_int) + ' era). Holders participated in ' +
                            'a raffle (Sponsored by ' +  era_organization.to_str() + ').',
            'eraId': era_id_int,
            'image': 'https://github.com/AfricaN3/LifeSaver-Contracts/blob/master/media/mascot.png',
            'name': 'life',
            'owner': self._owner,
            'tokenId': token_id_bytes,
            'tokenURI': 'https://github.com/AfricaN3/LifeSaver-Contracts/blob/master/media/mascot',
        }
        return exported

    def get_state_flat(self) -> Dict[str, Any]:
        """
        Gets the state of the life and returns the data in a flat format.
        :return: the life in a flat format
        """
        token_id_bytes: bytes = self._token_id
        era_id_bytes: bytes = self._era_id

        era_id_int: int = era_id_bytes.to_int()
        era: Era = get_era(era_id_bytes)
        era_organization: bytes = era.get_organization()

        life_attrs: List[Any] = [
            {
                'trait_type': 'eraId',
                'value': era_id_int
            }
        ]

        exported: Dict[str, Any] = {
            'name': 'life',
            'image': 'https://github.com/AfricaN3/LifeSaver-Contracts/blob/master/media/mascot.png',
            'tokenURI': 'https://github.com/AfricaN3/LifeSaver-Contracts/blob/master/media/mascot',
            'owner': self._owner,
            'tokenId': token_id_bytes.to_str(),
            'description': 'LifeSaver NFT #' + token_id_bytes.to_str() + '. This is a Soulbound token minted during ' + 
                            'a blood drive event ' + '(' + itoa(era_id_int) + ' era). Holders participated in ' +
                            'a raffle (Sponsored by ' +  era_organization.to_str() + ').',
            'attributes': life_attrs
        }
        return exported

    def get_token_id(self) -> bytes:
        """
        Getter for the life unique identifier
        @return: integer representing the unique identifier
        """
        return self._token_id

    def set_owner(self, owner: UInt160) -> bool:
        """
        Setter for the life owner
        @param owner: bytes representing the owner of the life
        @return: Boolean indicating success
        """
        self._owner = owner
        return True

    def set_timestamp(self) -> bool:
        """
        Setter for the life timestamp
        @return: Boolean indicating success
        """
        self._timestamp = time + 3600
        return True


@public
def makeTransferable(token_id: bytes) -> bool:
    """
    Makes a token transferable.

    The parameter token_id SHOULD be a valid NFT. If not, this method SHOULD throw an exception.

    :param token_id: the token for which to make transferable
    :type token_id: ByteString
    :return: Boolean indicating success.
    :raise AssertionError: raised if `token_id` is not a valid NFT or contract caller is not authorized.
    """
    tx = cast(Transaction, script_container)
    user: User = get_user(tx.sender)
    assert user.get_offline_mint(), 'User Permission Denied'

    life: Life = get_life(token_id)
    life_era_id: bytes = life.get_era_id()
    life_era: Era = get_era(life_era_id)

    is_era_admin: bool = life_era.get_admin() == tx.sender
    can_make_transferable: bool = user.can_initiate_transfer()
    is_authorized: bool = can_make_transferable or is_era_admin

    assert is_authorized, 'User Permission Denied'

    life.set_timestamp()
    save_life(life)
    return True


@public(safe=True)
def get_life(token_id: bytes) -> Life:
    """
    A factory method to get a life from storage
    :param token_id: the unique identifier of the life
    :return: The requested life
    """
    life_bytes: bytes = get_life_raw(token_id)
    return cast(Life, deserialize(life_bytes))


@public(safe=True)
def get_life_json(token_id: bytes) -> Dict[str, Any]:
    """
    Gets a dict representation of the life's base stats
    :param token_id: the unique life identifier
    :return: A dict representing the life
    """
    life: Life = get_life(token_id)
    return life.get_state()


@public(safe=True)
def get_life_json_flat(token_id: bytes) -> Dict[str, Any]:
    life: Life = get_life(token_id)
    return life.get_state_flat()


def get_life_raw(token_id: bytes) -> bytes:
    """
    Gets the serialized life definition
    :param token_id: the unique life identifier
    :return: a serialize life
    """
    return get(mk_token_key(token_id))


def save_life(life: Life) -> bool:
    """
    A factory method to persist a life to storage
    :param life: A life to save
    :return: A boolean representing the results of the save
    """
    token_id: bytes = life.get_token_id()
    put(mk_token_key(token_id), serialize(life))
    return True


def mk_token_key(token_id: bytes) -> bytes:
    return TOKEN_PREFIX + token_id
