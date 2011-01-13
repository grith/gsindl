#############################################################################
#
# Copyright (c) 2011 Russell Sim <russell.sim@gmail.com>
# Copyright (c) 2009 Victorian Partnership for Advanced Computing Ltd and
# Contributors.
# All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#############################################################################

from os import path

from M2Crypto import BIO, RSA, EVP, m2
from M2Crypto.util import no_passphrase_callback


class Getpget(object):
    """Class to allow m2crypto compat with the key class"""
    def __get__(self, obj, objtype):
        return obj._pubkey.pkey


def quiet_keygen_callback(p, n, out=None):
    pass


def generate_key(key=None, keySize=2048, callback=no_passphrase_callback):
    """This is a wrapper class for handling key pair generation.

    :param key: the :class:`str` or file path to the key
    :param keySize: The size of the key to be generated (default 2048)
    :param callback: a function that is called when outputting the key,
       it's used to encrypt the key before writing it.

    """
    if isinstance(key, str):
        key = key.strip()
        if key.startswith("-----BEGIN RSA PRIVATE KEY-----"):
            bio = BIO.MemoryBuffer(key)
            _key = RSA.load_key_bio(bio, callback)
        elif path.exists(key):
            keyfile = open(key)

            bio = BIO.File(keyfile)
            key = RSA.load_key_bio(bio, callback)

            _pubkey = EVP.PKey()
            _key = key
            _pubkey.assign_rsa(_key)
        else:
            raise ValueError("WTF")
    else:
        _pubkey = EVP.PKey()
        _key = RSA.gen_key(keySize, m2.RSA_F4, callback=quiet_keygen_callback)
        _pubkey.assign_rsa(_key)
    return _pubkey


def key_to_str(key):
    """
    This function print's a key unencrypted DANGERIOUS
    """
    bio = BIO.MemoryBuffer()
    key.save_key_bio(bio, cipher=None)
    return bio.read()
