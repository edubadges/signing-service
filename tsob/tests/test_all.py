import binascii
import os

import pytest

from tsob.keys import create_new_symkey


@pytest.fixture
def symmetric_key_params():
    return {
        "salt": binascii.hexlify(os.urandom(16)),
        "length": 32,
        "n": 2 ** 14,
        "r": 8,
        "p": 1,
        "password": "password",
    }


def test_key_length(self):
    # client.get()
    pass


def test_n_param_too_small(self):
    pass


def test_n_param_too_large(self):
    pass


def test_unsecure_r_param(self):
    pass


def test_unsecure_p_param(self):
    pass


def test_length_param_too_big(self):
    pass


def test_length_param_too_small(self):
    pass


def test_too_low_salt_entropy(self):
    pass


def test_without_salt(self):
    pass


def test_with_salt(self):
    """
    Create a new symmetric encryption key with provided salt.
    """
    local_input_params = self.input_params
    # local_input_params['salt'] = 'fbec1c1cb40f75e1bf22d20441dc9b7f'
    result = create_new_symkey(local_input_params)
    assert self.input_params['salt'].decode(), result['salt']


def test_same_symkey_with_same_params(self):
    pass


def test_symkey_creation_with_bytes_password(self):
    pass
