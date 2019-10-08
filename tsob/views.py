import binascii

from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

import tsob.badges
import tsob.keys
from tsob.keys import (InvalidEncryptedKey, PrivateKeyNotSecureError,
                       ReEncryptionError, SymmetricKeyNotSecureError,
                       SymmetricKeyParamError)


def validate_request(request, request_params):
    """
    Need to add recursive function to loop through nested data. Or create serializers, which is better done after
    the dictionaries are translated into (data)classes.
    """
    data = request.data
    for key in request_params:
        if key not in data:
            raise ValidationError(key + " not provided.")
    return data


def hexlify_decode(data):
    """
    :param data: A dictionary containing some items that are byte encoded.
    :return: Fully decoded dictionary where previously decoded items are hexlified for transfer and storage.
    """
    for key in data:
        if isinstance(data[key], bytes):
            data[key] = binascii.hexlify(data[key]).decode()
    return data


def unhexlify_encode(data):
    """
    :param data: A dictionary containing some items that need to be unhexlified and then decoded.
    :return: Fully unhexlified and decoded dictionary.
    """
    encoding_list = ['initialization_vector', 'encrypted_private_key', 'tag', 'associated_data']
    for key in data:
        if key in encoding_list:
            data[key] = binascii.unhexlify(data[key].encode())
    return data


def exception_handler(exception):
    """
    :param exception: An exception that is raised somewhere in the process.
    :return: A valid response based on the exception class.
    """
    if isinstance(exception, ValidationError):
        response = {"message": "Data format not correct: " + str(exception.detail[0])}
        return Response(data=response, status=status.HTTP_400_BAD_REQUEST)

    if isinstance(exception, (SymmetricKeyNotSecureError, SymmetricKeyParamError)):
        response = {"message": "Data input not correct: " + str(exception)}
        return Response(data=response, status=status.HTTP_400_BAD_REQUEST)

    if isinstance(exception_handler, (ReEncryptionError, InvalidEncryptedKey)):
        response = {"message": "Encrypted key error: " + str(exception.detail[0])}
        return Response(data=response, status=status.HTTP_400_BAD_REQUEST)

    if isinstance(exception_handler, PrivateKeyNotSecureError):
        response = {"message": "Private key error: " + str(exception.detail[0])}
        return Response(data=response, status=status.HTTP_400_BAD_REQUEST)

    if isinstance(exception_handler, AttributeError):
        response = {"message": "Attribute error: " + str(exception.detail[0])}
        return Response(data=response, status=status.HTTP_400_BAD_REQUEST)

    if isinstance(exception, ValueError):
        response = {"message": "Value of parameter not correct: " + str(exception)}
        return Response(data=response, status=status.HTTP_400_BAD_REQUEST)

    if isinstance(exception, Exception):
        response = {"message": "Something went wrong, please contact your IT admin.: " + str(exception)}
        return Response(data=response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(http_method_names=['POST'])
def create_new_symmetric_key(request):
    """
    :param request: HTTP POST request to receive a new symmetric key.
    :return: JSON object containing a new symmetric key based on its parameters.
    """
    request_params = ['salt', 'length', 'n', 'r', 'p', 'password']

    try:
        data = validate_request(request, request_params)
        symmetric_key = tsob.keys.get_symmetric_key_by_params(data, new=True)
        return Response(symmetric_key)

    except Exception as e:
        return exception_handler(e)


@api_view(http_method_names=['POST'])
def create_new_private_key(request):
    """
    :param request: HTTP POST request to receive a new private key.
    :return: JSON object containing a new private key.
    """
    request_params = ['salt', 'length', 'n', 'r', 'p', 'password']

    try:
        data = validate_request(request, request_params)
        if 'key_size' not in data:
            result = tsob.keys.create_new_private_key(data)
        else:
            key_size = data.pop('key_size')
            result = tsob.keys.create_new_private_key(data, key_size)

        result = hexlify_decode(result)

    except Exception as e:
        return exception_handler(e)

    return Response(result)


@api_view(http_method_names=['POST'])
def re_encrypt_private_keys(request):
    """
    :param request: HTTP POST request with encrypted private keys that need to be re-encrypted.
    :return: JSON object containing the re-encrypted private keys.
    """
    request_params = ['old_symmetric_key', 'new_symmetric_key', 'private_key_list']  # Need check for nested keys.

    try:
        data = validate_request(request, request_params)
        for enc_pk in data['private_key_list']:
            unhexlify_encode(enc_pk)

        result = tsob.keys.re_encrypt_private_keys(
            data['old_symmetric_key'],
            data['new_symmetric_key'],
            data['private_key_list'],
        )

        for newly_encrypted_private_key in result:
            hexlify_decode(newly_encrypted_private_key)

    except Exception as e:
        return exception_handler(e)

    return Response(result)


@api_view(http_method_names=['POST'])
def sign_badges(request):
    """
    :param request: HTTP POST request containing badges to be signed including the private key to sign it.
    :return: JSON object containing the signed open badges in JWS format.
    """
    request_params = ['list_of_badges', 'symmetric_key', 'private_key']  # Need check for nested keys.

    try:
        data = validate_request(request, request_params)
        unhexlify_encode(data['private_key'])
        result = tsob.badges.sign_badges(data['symmetric_key'], data['list_of_badges'], data['private_key'])
        hexlify_decode(result['encrypted_private_key_used'])

    except Exception as e:
        return exception_handler(e)

    return Response(result)


@api_view(http_method_names=['POST'])
def deep_validate(request):
    """
    :param request: HTTP POST request with a list of signed badges in JWS format including the supposed private key
    used to sign it.
    :return: JSON object containing a list of validated badges.
    """
    request_params = ['signed_badges', 'symmetric_key', 'private_key']  # Need check for nested keys.
    try:
        data = validate_request(request, request_params)
        unhexlify_encode(data['private_key'])
        result = tsob.badges.deep_validate(data['symmetric_key'], data['signed_badges'], data['private_key'])
        hexlify_decode(result['encrypted_private_key_used'])

    except Exception as e:
        return exception_handler(e)

    return Response(result)
