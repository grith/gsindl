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
from M2Crypto import X509, m2, BIO, ASN1, Err
from os import path
import logging
import time
from key import Key
from util import _build_name_from_string
from M2Crypto.util import no_passphrase_callback

log = logging.getLogger('arcs.gsi')

Att_map = {'extendedkeyusage': 'extendedKeyUsage',
           'keyusage': 'keyUsage',
           'certificatepolicies': 'certificatePolicies',
           'subjectaltname': 'subjectAltName',
           'proxycertinfo': 'proxyCertInfo',
          }

multi_attrs = {'keyusage': {'digitalsignature': 'Digital Signature',
                            'keyencipherment': 'Key Encipherment',
                            'dataencipherment': 'Data Encipherment',
                            }
               ,'extendedkeyusage': {'clientauth': 'clientAuth',
                                     }
              }


class CertificateRequest:
    """This is a wrapper class for handling certificate request generation.

    :param request: either a PEM :class:`str` a DER :class:`str`
    :param path: the path to the certificate request file
    :param key: if sepecified this will be wrapped in a :class:`~arcs.gsi.key.Key`
    :param keySize: The size of the key to be generated (default 2048)
    :param dn: the DN string of M2Crypto X509_Name
    :param extensions: a :class:`list` of :class:`dict` objects containing extensions

    """
    def __init__(self, request=None, path=None, dn=None,
                 keySize=2048, key=None, extensions=None):

        self.signed = False

        # Create public key object
        if key and not request:
            self._key = key
        else:
            self._key = Key(keySize=keySize)

        # Create certificate._request
        if request:
            self._request = request
            if isinstance(request, str):
                if request.startswith("-----BEGIN CERTIFICATE REQUEST-----"):
                    bio = BIO.MemoryBuffer(request)
                    cptr = m2.x509_req_read_pem(bio._ptr())
                    if cptr is None:
                        raise X509.X509Error(Err.get_error())
                    self._request = X509.Request(cptr, _pyfree=1)
                elif ord(request[0]) == 48:
                    bio = BIO.MemoryBuffer(request)
                    cptr = m2.d2i_x509_req(bio._ptr())
                    if cptr is None:
                        raise X509.X509Error(Err.get_error())
                    self._request = X509.Request(cptr, _pyfree=1)
                elif path.exists(request):
                    reqfile = open(request)
                    bio = BIO.File(reqfile)
                    self._request = X509.load_request_bio(bio)
                else:
                    raise ValueError('WFT')
        else:
            self._request = X509.Request()
            self._request.set_pubkey(self._key)
            self._request.set_version(0)

        if dn:
            self.set_dn(dn)

        if extensions:
            self.add_extensions(extensions)



    def set_dn(self, dn):
        """
        set the dn of the certificate request

        :param dn: either a string or an X509_Name object
        """

        if isinstance(dn, X509.X509_Name):
            self._request.set_subject_name(dn)
        elif isinstance(dn, str):
            self._request.set_subject_name(_build_name_from_string(dn))
        else:
            raise ValueError('WFT')
        self._signed = False


    def add_extensions(self, extensions):
        """
        add extenstions to the certificate. Takes a list of dictionary and
        converts them into extension objects.

        :param extensions: a :class:`list` of :class:`dict` objects containing extensions

        Example of adding an extension::

            >>> import arcs.gsi.certificate
            >>> r = arcs.gsi.certificate.CertificateRequest()
            >>> r.add_extensions([{'name':'subjectAltName' ,'critical':0, 'value':'russell@vpac.org'}])
        """
        extstack = X509.X509_Extension_Stack()

        sslower = lambda s: s.lower().replace(' ','')

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
        self._request.add_extensions(extstack)
        self._signed = False


    def sign(self, md='sha1'):
        """
        sign the certificate request, must be done to finiliaze the :class:`CertificateRequest`

        :param md: the hash to use when signing the :class:`CertificateRequest`
        """
        self._request.sign(self._key, md)
        self._signed = True


    def get_cert_req(self):
        """return the certificate request object"""
        if not self._signed:
            self.sign()
        return self._request

    def get_key(self):
        """return the private key pair"""
        return self._key

    def get_pubkey(self):
        """return the public key from the certificate request"""
        return self._request.get_pubkey()

    def as_dict(self):
        """return the dictionary representation of the certificate request"""
        c = {}
        c['version'] = self._request.get_version()
        c['subject'] = self._request.get_subject().as_text()
        # XXX Needs to return the extensions too.

    def __str__(self):
        return self._request.as_text()


    def __repr__(self):
        return self._request.as_pem()


class Certificate:
    def __init__(self, certificate=None, key=None,
                 callback=no_passphrase_callback):
        self._key = None
        if key:
            if isinstance(key, Key):
                self._key = key
            else:
                self._key = Key(key, callback=callback)

        if isinstance(certificate, str):
            if certificate.startswith("-----BEGIN CERTIFICATE-----"):
                self._certificate = X509.load_cert_string(str(certificate),
                                                          X509.FORMAT_PEM)
            elif path.exists(certificate):
                certfile = open(certificate)
                bio = BIO.File(certfile)
                self._certificate = X509.load_cert_bio(bio)
            else:
                raise ValueError("WTF")
        else:
            self._certificate = X509.X509()
            if not key:
                key = Key()
            self._key = key
            self.set_pubkey(self._key)


    def set_version(self, version):
        self._certificate.set_version(version)


    def get_dn(self):
        return self.get_subject().as_text()


    def set_dn(self, dn):
        if isinstance(dn, X509.X509_Name):
            self._certificate.set_subject_name(dn)
        elif isinstance(dn, str):
            self._certificate.set_subject_name(_build_name_from_string(dn))
        else:
            raise ValueError('WFT')


    def add_extensions(self, extensions):

        for e in extensions:
            self.add_extension(e)

        self._signed = False


    def add_extension(self, e):
        sslower = lambda s: s.lower().replace(' ','')
        name = e['name']
        key = sslower(name)
        critical = e['critical']
        if key in multi_attrs:
            e['value'] = ', '.join([multi_attrs[key][sslower(v)]
                           for v in e['value'].split(',')])
        self._certificate.add_ext(X509.new_extension(Att_map[key],
                                         e['value'],
                                         critical=int(critical)))


    def set_issuer_name(self, name):
        if isinstance(name, X509.X509_Name):
            self._certificate.set_issuer_name(name)
        elif isinstance(name, str):
            self._certificate.set_issuer_name(_build_name_from_string(name))
        else:
            raise ValueError('WFT')


    def set_times(self, lifetime=43200):
        """
        Sets the lifetime of the certificate
        Defaults to 12 hours
        """
        not_before = ASN1.ASN1_UTCTIME()
        not_after = ASN1.ASN1_UTCTIME()
        not_before.set_time(int(time.time()) - 300)
        not_after.set_time(int(time.time()) + lifetime )
        self._certificate.set_not_before(not_before)
        self._certificate.set_not_after(not_after)

    def get_times(self):
        """
        Return tuple containing not before and not after times
        """
        return (self._certificate.get_not_before(), self._certificate.get_not_after())


    def sign(self, key, md='sha1'):
        self._certificate.sign(key, md)


    def set_pubkey(self, pubkey):
        self._certificate.set_pubkey(pubkey)


    def get_ext(self, extension):
        """Get X509 extension by name"""
        return self._certificate.get_ext(extension)


    def get_serial_number(self):
        return self._certificate.get_serial_number()


    def get_issuer(self):
        return self._certificate.get_issuer()


    def get_version(self):
        return self._certificate.get_version()


    def get_subject(self):
        return self._certificate.get_subject()


    def get_pubkey(self):
        return self._certificate.get_pubkey()


    def get_key(self):
        if self._key:
            return self._key
        raise ValueError("No Key?")


    def __str__(self):
        return self._certificate.as_text()


    def __repr__(self):
        return self._certificate.as_pem()

    def as_der(self):
        return self._certificate.as_der()

