#############################################################################
#
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


class Key:
    def __init__(self, key=None, keySize=2048, callback=no_passphrase_callback):
        self._passphrase_callback = callback
        if isinstance(key, str):
            if path.exists(key):
                keyfile = open(key)

                bio = BIO.File(keyfile)
                key = RSA.load_key_bio(bio, self._passphrase_callback)

                self._key = key
            else:
                raise ValueError("WTF")
        else:
            self._pubkey = EVP.PKey()
            self._key = RSA.gen_key(keySize, m2.RSA_F4)
            self._pubkey.assign_rsa(self._key)


    pkey = Getpget()


    def __str__(self):
        bio = BIO.MemoryBuffer()
        self._key.save_key_bio(bio, cipher=None)
        return bio.read()

