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

import time
import logging
from os import path

from M2Crypto import X509, m2, BIO, ASN1, Err
from M2Crypto.util import no_passphrase_callback

from gsindl.key import generate_key
from gsindl.util import _build_name_from_string

log = logging.getLogger('gsindl')

Att_map = {'extendedkeyusage': 'extendedKeyUsage',
           'keyusage': 'keyUsage',
           'certificatepolicies': 'certificatePolicies',
           'subjectaltname': 'subjectAltName',
           'proxycertinfo': 'proxyCertInfo',
          }

multi_attrs = {'keyusage': {'digitalsignature': 'Digital Signature',
                            'keyencipherment': 'Key Encipherment',
                            'dataencipherment': 'Data Encipherment',
                            },
               'extendedkeyusage': {'clientauth': 'clientAuth',
                                    }
              }


def generate_request(dn=None, request=None, path=None,
                     keySize=2048, key=None, extensions=None):
    """This funciton is for certificate request generation.

    :param request: either a PEM :class:`str` a DER :class:`str`
    :param path: the path to the certificate request file
    :param key: if sepecified this will be wrapped in
       a :class:`~gsindl.key.Key`
    :param keySize: The size of the key to be generated (default 2048)
    :param dn: the DN string of M2Crypto X509_Name
    :param extensions: a :class:`list` of :class:`dict` objects
       containing extensions

    """

    # Create public key object
    if key and not request:
        _key = key
    else:
        _key = generate_key(keySize=keySize)

    # Create certificate._request
    if request:
        _request = request
        if isinstance(request, str):
            if request.startswith("-----BEGIN CERTIFICATE REQUEST-----"):
                bio = BIO.MemoryBuffer(request)
                cptr = m2.x509_req_read_pem(bio._ptr())
                if cptr is None:
                    raise X509.X509Error(Err.get_error())
                _request = X509.Request(cptr, _pyfree=1)
            elif ord(request[0]) == 48:
                bio = BIO.MemoryBuffer(request)
                cptr = m2.d2i_x509_req(bio._ptr())
                if cptr is None:
                    raise X509.X509Error(Err.get_error())
                _request = X509.Request(cptr, _pyfree=1)
            elif path.exists(request):
                reqfile = open(request)
                bio = BIO.File(reqfile)
                _request = X509.load_request_bio(bio)
            else:
                raise ValueError('WFT')
    else:
        _request = X509.Request()
        _request.set_pubkey(_key)
        _request.set_version(0)

    if dn:
        if isinstance(dn, X509.X509_Name):
            _request.set_subject_name(dn)
        elif isinstance(dn, str):
            _request.set_subject_name(_build_name_from_string(dn))
        else:
            raise ValueError("the DN passes in isn't either a "
                             "X509_Name or string")

    if extensions:
        extstack = X509.X509_Extension_Stack()

        sslower = lambda s: s.lower().replace(' ', '')

        for e in extensions:
            name = e['name']
            key = sslower(name)
            critical = e['critical']
            if key in multi_attrs:
                e['value'] = ', '.join([multi_attrs[key][sslower(v)]
                               for v in e['value'].split(',')])
            extstack.push(X509.new_extension(Att_map[key],
                                             e['value'],
                                             critical=int(critical)))
        _request.add_extensions(extstack)

    return _request, _key


def generate_certificate(dn=None, certificate=None,
                         key=None, version=2,
                         lifetime=43200,
                         extensions=None,
                         issuer=None,
                         callback=no_passphrase_callback):
    _key = None
    if key:
        _key = key

    if isinstance(certificate, str):
        if certificate.startswith("-----BEGIN CERTIFICATE-----"):
            _certificate = X509.load_cert_string(str(certificate),
                                                 X509.FORMAT_PEM)
        elif path.exists(certificate):
            certfile = open(certificate)
            bio = BIO.File(certfile)
            _certificate = X509.load_cert_bio(bio)
        else:
            raise ValueError("WTF")
    else:
        _certificate = X509.X509()
        if not key:
            key = generate_key()
        _key = key
        _certificate.set_pubkey(_key)

    if dn:
        if isinstance(dn, X509.X509_Name):
            _certificate.set_subject_name(dn)
        elif isinstance(dn, str):
            _certificate.set_subject_name(_build_name_from_string(dn))
        else:
            raise ValueError('invalid dn')

    # set version
    _certificate.set_version(version)

    # set times
    not_before = ASN1.ASN1_UTCTIME()
    not_after = ASN1.ASN1_UTCTIME()
    not_before.set_time(int(time.time()) - 300)
    not_after.set_time(int(time.time()) + lifetime)
    _certificate.set_not_before(not_before)
    _certificate.set_not_after(not_after)

    # set issuer
    if issuer:
        if isinstance(issuer, X509.X509_Name):
            _certificate.set_issuer_name(issuer)
        elif isinstance(issuer, str):
            _certificate.set_issuer_name(_build_name_from_string(issuer))
        else:
            raise ValueError('invalid issuer')

    if extensions:
        for e in extensions:
            sslower = lambda s: s.lower().replace(' ', '')
            name = e['name']
            key = sslower(name)
            critical = e['critical']
            if key in multi_attrs:
                e['value'] = ', '.join([multi_attrs[key][sslower(v)]
                                        for v in e['value'].split(',')])
            _certificate.add_ext(X509.new_extension(Att_map[key],
                                                    e['value'],
                                                    critical=int(critical)))

    return _certificate, _key
