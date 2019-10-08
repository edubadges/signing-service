import hashlib
import json

from Crypto.PublicKey import RSA
from jose import JWSError, jws

from tsob.keys import get_keys, get_symmetric_key_by_params


class SigningError(Exception):
    pass


class BadgeValidationError(Exception):
    pass


def verify(signed_badge, public_key, badge_id):
    """
    Verify the signed badge with public key.

    :param signed_badge: The signature containing the payload. eg Signed Badge
    :param public_key: Public key corresponding to the private key used to sign the payload.
    :return: Returns the payload in bytes after verification with the public key.
    """
    try:
        payload_bytes = jws.verify(
            signed_badge,
            public_key,
            algorithms='RS256',
        )
    except JWSError:
        raise BadgeValidationError("Signature verification failed for: " + badge_id + "- JWS signature not correct.")
    return payload_bytes


def validate_badge(signed_badge, public_key, badge_id):
    """
    Validating badges by verifying the signatures with the provided public keys.

    Future implementations could also make use of the openbadges-validator-core to verify the inside of the assertion.

    :param signed_badge: Signed (jws) badge.
    :param public_key: Corresponding public key to private key used for signing.
    :param badge_id: UUID of the badge.
    :return: Dictionary with badge_id, if the signature is valid and if so, the SHA256 hash of the assertion/payload.
    """
    try:
        badge_bytes = verify(signed_badge, public_key, badge_id)

        badge = json.loads(badge_bytes)

        if not badge['badge']['issuer']['publicKey']['publicKeyPem'] == public_key:
            raise BadgeValidationError(
                "Public key from encrypted private key is not the same as public key in signed badge.",
                badge['id'],
            )

        badge_hash = hashlib.sha256(badge_bytes).hexdigest()

        return {
            "badge_id": badge_id,
            "valid": True,
            "badge_hash": badge_hash,
        }
    except UnboundLocalError:
        return {
            "badge_id": badge_id,
            "valid": False,
            "badge_hash": None,
        }


def normalize(payload):
    """
    W3C's standard on normalization (eg. canonicalization) is still in draft. For now JSON is sorted by keys and
    all blank space is removed.

    To be able to eventually use normalization, every node in the graph needs an unique ID field.

    This is an example pf a normalization function to generate normalized RDF format payloads:
        normalized_json = jsonld.normalize(payload, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})
    """

    normalized_payload = json.dumps(
        payload,
        sort_keys=True,
        separators=(',', ':'),
    ).encode()  # Temporary 'semi' normalization of JSON assertion.

    payload_hash = hashlib.sha256(normalized_payload).hexdigest()

    return normalized_payload, payload_hash


def sign(payload, private_key):
    """
    Concise signing function to create JWS signature with payload.

    Future implementations could also add EdDSA as algo's.

    :param payload: Payload to sign
    :param private_key: Private key to sign with
    :return: Signature in JWS format
    """

    return jws.sign(payload, RSA.importKey(private_key).exportKey().decode(), algorithm='RS256')


def sign_badges(symmetric_key_params, list_of_badges, encrypted_private_key):
    """
    Signing the badges that are provided with the also provided private key.

    :param symmetric_key_params: Params used for retrieving a symmetric key. Here used for decrypting the private key.
    :param list_of_badges: The list of plaintext badges provided that need to be signed.
    :param encrypted_private_key: A dictionary containing the encrypted private key and its associated parameters.
    :return: A list of signed badge dictionaries containing the singned badge signature, id, and badge hash.
    """
    decryption_key = get_symmetric_key_by_params(symmetric_key_params)

    private_key, public_key = get_keys(decryption_key, encrypted_private_key)

    signed_badges = {
        "encrypted_private_key_used": encrypted_private_key,
        "signed_badges": [],
    }

    for badge in list_of_badges:
        if badge['badge']['issuer']['publicKey']['id'] != badge['verification']['creator']:
            raise SigningError("Public key owner is not Issuer.")

        normalized_badge, badge_hash = normalize(badge)

        signature = sign(normalized_badge, private_key)

        signed_badge = {
            "badge_id": badge['id'],
            "signature": signature,
            "plain_badge": json.loads(normalized_badge.decode()),
        }

        if badge_hash != validate_badge(signature, public_key, badge['id'])['badge_hash']:
            raise SigningError("Badge hashes not equal, something went wrong in handling the payload during signing.")

        signed_badges['signed_badges'].append(signed_badge)

    return signed_badges


def deep_validate(symmetric_key_params, signed_badges, encrypted_private_key):
    """
    Deep validation done on the signatures by validation of the signature with the public key actually derived from
    the also provided private key.

    Currently stops the process and returns a BadgeValidationError when a badge cannot be validated. In the future it
    may be useful to validate all and set valid to True/False for each badge.

    :param symmetric_key_params: Params used for retrieving a symmetric key. Here used for decrypting the private key.
    :param signed_badges: The signed badges (JWS signatures) .
    :param encrypted_private_key: Provided private key for validation.
    :return: A list with dictionaries containing info on the signed badges (valid or not).
    """
    validated_badges = {
        "encrypted_private_key_used": encrypted_private_key,
        "validated_badges": [],
    }

    decryption_key = get_symmetric_key_by_params(symmetric_key_params)

    private_key, public_key = get_keys(decryption_key, encrypted_private_key)

    for badge in signed_badges:
        validated_badge = validate_badge(badge['signature'], public_key, badge['badge_id'])
        validated_badges['validated_badges'].append(validated_badge)
    return validated_badges
