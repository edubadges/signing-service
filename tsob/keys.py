import binascii
import hashlib
import os
from datetime import datetime

from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class SymmetricKeyNotSecureError(ValueError):
    pass


class PrivateKeyNotSecureError(ValueError):
    pass


class PrivateKeyTypeError(Exception):
    pass


class NotBytesError(Exception):
    pass


class SymmetricKeyParamError(Exception):
    pass


class ReEncryptionError(Exception):
    pass


class InvalidEncryptedKey(InvalidTag):
    pass


def derive_symmetric_key(password, salt, length=32, n=2 ** 20, r=8, p=1):
    """
    Using input (password) that should be unique and only known to the owner, a symmetric key is derived.
    (Future implementation: Refactor the returned object to a SymmetricKey (data)class instead of a dictionary.)

    :param password: The password of the owner of the symmetric key. Used to produce the symmetric key.
    :param salt: A random bytes string for entropic input.
    :param length: The symmetric key size in bits, where length * 8 == security. Keep at 32 for now,
    :param n: N param of Scrypt algorithm. Recommended size for encryption is 1048576 (which is 2 ** 20).
    :param r: r param of Scrypt algorithm. Memory hardness. Keep at 8 for now.
            See:https://stackoverflow.com/questions/11126315/what-are-optimal-scrypt-work-factors
    :param p: p param of Scrypt algorithm. Parallelization security, keep 1 for now. May change in the future.
    :return: The symmetric encryption key to encrypt and decrypt data. And the public data used for the derivation.
    The public data (params) are needed to create the symmetric key later again.
    """

    if length != 32:
        raise SymmetricKeyNotSecureError("Not secure enough param (length) for key derivation function. - Must be 32.")

    if n < 16384:
        raise SymmetricKeyNotSecureError("Not secure enough param (N) for key derivation function. - Must be > 16384")

    if r != 8:
        raise SymmetricKeyNotSecureError("Not secure enough param (r) for key derivation function. - Must be 8.")

    if p != 1:
        raise SymmetricKeyNotSecureError("Not secure enough param (p) for key derivation function. - Must be 1.")
    derived_symmetric_key = scrypt(
        salt=salt,
        key_len=length,
        N=n,
        r=r,
        p=p,
        password=password,
    )  # Initialize key-derivation-function

    return {
        "salt": salt,
        "length": length,
        "n": n,
        "r": r,
        "p": p,
        "symmetric_key": derived_symmetric_key,
    }


def generate_rsa_private_key(key_size: int = 4096):
    """
    Generates RSA private key.
    Specifically not using RSA.generate (significantly slower than cryptography.hazmat due to prime# filtering).

    :param key_size: Default is 4096, minimum is 2048 for security reasons.
    :return: RSA private key
    """
    if key_size < 2048:
        raise PrivateKeyNotSecureError("Private key is not secure enough, needs bigger key size (>= 2048.")

    return rsa.generate_private_key(65537, key_size, default_backend())  # 65537 is the standard exponent used for RSA.


def get_public_key_from_private_key(private_key):
    """
    Depending on different RSA private keys, extrapolates the corresponding public key.
    (Future implementation: Also support other key algorithms.)

    :param private_key: RSA private key
    :return: Returns RSA public key corresponding to private key (bytes or class).
    """

    if isinstance(private_key, bytes):
        return RSA.importKey(private_key).publickey().exportKey('PEM').decode()
    else:
        PrivateKeyTypeError("Private key object is not in PEM-format.")


def transform_private_key_to_bytes(private_key):
    """
    Convert private key object to bytes (PEM) using PKCS8 format. For now it seems PKCS8 is the right format.

    :param private_key: RSA private key object
    :return: Private key in PEM format
    """

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def hash_bytes(data):
    """
    Hash data (for example, public key in bytes, symmetric key in bytes or the badge assertion in bytes).

    :param data:  Data in bytes format
    :return: Human readable SHA256 hash of the data.
    """

    if not isinstance(data, bytes):
        raise NotBytesError("The data should be provided in bytes format.")
    else:
        return hashlib.sha256(data).hexdigest()


def encrypt_private_key(symmetric_key, private_key, associated_data=datetime.utcnow().strftime('%d-%b-%Y').encode()):
    """
    Encrypt private key (in bytes) with symmetric encryption key using the AES256-GCM schema.

    :param symmetric_key: Symmetric key in bytes to encrypt and decrypt the private key(s).
    :param private_key: Private key, unencrypted and in bytes (PEM) format.
    :param associated_data: Data associated with this specific private key. If not provided it is assumed a new
    private key, which gets the current day (UTC) as associated data.
    :return: A dictionary containing data and params relating to the encrypted private key. The params included
    are needed to decrypt the private key. Next step is to turn this into a (data)class.
    """

    initialization_vector = os.urandom(12)  # Initialize GCM with enough randomness. Q is 12 (96 bits) large enough?

    encryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.GCM(initialization_vector),
        backend=default_backend(),
    ).encryptor()

    encryptor.authenticate_additional_data(associated_data)  # Authenticate encryption with associated data.

    encrypted_private_key = encryptor.update(private_key) + encryptor.finalize()  # Encrypt private key.

    return {
        "initialization_vector": initialization_vector,
        "encrypted_private_key": encrypted_private_key,
        "tag": encryptor.tag,
        "associated_data": associated_data,
    }


def decrypt_private_key(symmetric_key, encrypted_private_key):
    """
    Decrypt private key (in bytes) with symmetric encryption key using the AES256-GCM schema.

    :param symmetric_key: Symmetric key in bytes to encrypt and decrypt the private key(s).
    :param encrypted_private_key: Private key in dictionary with associated encryption params.
    :return: Private key in bytes (PEM) format.
    """

    decryptor = Cipher(
        algorithms.AES(symmetric_key),
        modes.GCM(
            encrypted_private_key['initialization_vector'],
            encrypted_private_key['tag'],
        ),
        backend=default_backend(),
    ).decryptor()  # Create decryptor

    decryptor.authenticate_additional_data(
        encrypted_private_key['associated_data'],
    )  # Authenticate using the associated data.

    try:
        decrypted_private_key = decryptor.update(encrypted_private_key['encrypted_private_key']) + decryptor.finalize()
        return decrypted_private_key

    except InvalidTag:
        raise InvalidEncryptedKey("Not able to decrypted private key. - Derived tag invalid.")


def get_keys(symmetric_key, encrypted_private_key):
    private_key = decrypt_private_key(symmetric_key, encrypted_private_key)
    public_key = get_public_key_from_private_key(private_key)
    return private_key, public_key


def get_symmetric_key_by_params(symmetric_key_params, new=False):
    """
    Get the symmetric key by it's params. If 'new' flag is set to True, salt is generated and new key is returned.

    :param symmetric_key_params: Params used for retrieving a symmetric key.
    :param new: Flag used for creating a new symmetric key (with random entropy).
    :return: A new symmetric key with the 'new' flag set to True OR a symmetric key dictionary with the symmetric
    key and its creation parameters.
    This 2nd return option also return the hash of the password used in key creation for requestor of key creation
    to check password in client vs used in key creation. Maybe change this to UUID later?
    In the future this should return a symmetric key (data)class.
    """

    if new:
        symmetric_key_params['salt'] = binascii.hexlify(os.urandom(16))  # Randomness generated for new symmetric key.

    if not symmetric_key_params['salt'] or symmetric_key_params['salt'].isspace():
        raise SymmetricKeyParamError("No salt provided.")  # If no salt is provided and not a new key, raise error.

    if not symmetric_key_params['password'] or symmetric_key_params['password'].isspace():
        raise SymmetricKeyParamError("No password provided.")  # If no salt is provided and not a new key, raise error.

    symmetric_key = derive_symmetric_key(
        password=symmetric_key_params['password'],
        salt=symmetric_key_params['salt'],
        length=symmetric_key_params['length'],
        n=symmetric_key_params['n'],
        r=symmetric_key_params['r'],
        p=symmetric_key_params['p'],
    )  # Symmetric key derived from input params.

    if new:
        return {
            "salt": symmetric_key_params['salt'].decode(),
            "length": symmetric_key_params['length'],
            "n": symmetric_key_params['n'],
            "r": symmetric_key_params['r'],
            "p": symmetric_key_params['p'],
            "password_hash": hash_bytes(symmetric_key_params['password'].encode()),
            "hash_of_symmetric_key": hash_bytes(symmetric_key['symmetric_key']),
        }
    else:
        return symmetric_key['symmetric_key']


def create_new_private_key(symmetric_key_params, key_size=4096):
    """
    Create a new private key for signing, returns the encrypted private key including creation params.

    There is also a hash of the public key returned. The hash of the public key is used as verification by the
    private key owner to see if a corresponding private key has been used for signing of data (that includes
    the public key).

    The time of creation (in UTC) is also provided so that it is know from what time the private key was valid.
    The format is currently UTC/Zulu (seen by the 'Z' at the end). But can be others, see below for 2 examples:
    # encrypted_private_key['time_created'] = datetime.utcnow().isoformat(timespec="seconds") + '+00:00'
    # encrypted_private_key['time_created'] = datetime.utcnow().isoformat(timespec="seconds") + offset

    :param symmetric_key_params: Params used for retrieving a symmetric key. Here used for encrypting private key.
    :param key_size: The size of the RSA private key. Must be >= 2048. 4096 is preferred.
    :return: A dictionary containing the encrypted private key with its creation params and a hash of the public key.
    Eventually this dictionary should be refactored to a (data)class.
    """

    encryption_key = get_symmetric_key_by_params(symmetric_key_params)

    private_key = generate_rsa_private_key(key_size)
    private_key = transform_private_key_to_bytes(private_key)

    encrypted_private_key = encrypt_private_key(encryption_key, private_key)

    encrypted_private_key['time_created'] = datetime.utcnow().isoformat(timespec="seconds") + 'Z'

    public_key = get_public_key_from_private_key(private_key)

    encrypted_private_key['public_key'] = public_key

    return encrypted_private_key


def re_encrypt_private_keys(old_symmetric_key_params, new_symmetric_key_params, list_of_encrypted_private_keys):
    """
    Re-encrypt the provided list of encrypted private keys with the new provided symmetric key us its params.

    The associated data that corresponds to the encrypted private key is added back in as associated data when
    re-encrypting.

    Hashed of the public keys are compared to see if no incorrect private key params were provided by the user.

    The creation time of the private key is re-added to the re-encrypted private key, to make sure that the initial
    private key creation.usage has not changed.

    :param old_symmetric_key_params: Params used for retrieving a symmetric key. Here used for decrypting private keys.
    :param new_symmetric_key_params: Params used for retrieving a symmetric key. Here used for encrypting private keys.
    :param list_of_encrypted_private_keys: A list of dictionaries containing encrypted private keys and their
    associated decryption and creation parameters.
    :return: A list of dictionaries containing encrypted private keys and their associated encryption and creation
    parameters.
    """

    old_symmetric_key = get_symmetric_key_by_params(old_symmetric_key_params)  # Symmetric key to decrypt private keys.
    new_symmetric_key = get_symmetric_key_by_params(new_symmetric_key_params)  # Symmetric key to encrypt private keys.

    old_encrypted_private_keys = list_of_encrypted_private_keys
    new_encrypted_private_keys = []

    for old_encrypted_private_key in old_encrypted_private_keys:

        private_key, public_key = get_keys(old_symmetric_key, old_encrypted_private_key)

        if old_encrypted_private_key['public_key'] != public_key:
            raise ReEncryptionError('Public keys not equal. Meaning private keys are not equal either!')

        newly_encrypted_private_key = encrypt_private_key(
            new_symmetric_key,
            private_key,
            old_encrypted_private_key['associated_data'],
        )

        newly_encrypted_private_key['public_key'] = public_key

        newly_encrypted_private_key['time_created'] = old_encrypted_private_key['time_created']

        new_encrypted_private_keys.append(newly_encrypted_private_key)

    return new_encrypted_private_keys
