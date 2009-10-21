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

from M2Crypto import EVP, m2, X509
import struct

from certificate import Certificate

MBSTRING_ASC  = 0x1000 | 1
PCI_VALUE_FULL = "critical, language:Inherit all"
PCI_VALUE_LIMITED = "critical, language:1.3.6.1.4.1.3536.1.1.1.9"


class ProxyCertificate:
    """This is a wrapper class for handling proxy certificate generation.

    :param request: if specified this will be wrapped in a :class:`~arcs.gsi.certificate.Certificate` object
    :param proxykey: the key used to sign the proxy, if sepecified this will be wrapped in a :class:`~arcs.gsi.key.Key` object
    :param full: whether this is a full proxy or not

    """
    def __init__(self, certificate, proxykey=None, full=True):
        if isinstance(certificate, Certificate):
            self._certificate = certificate
        elif isinstance(certificate, ProxyCertificate):
            self._certificate = certificate._proxy
        else:
            self._certificate = Certificate(certificate)
        self._full = full

        self._proxy = Certificate(key=proxykey)

        self._proxy.set_version(2)
        self.set_serial_number()
        issuer = self._certificate.get_subject()
        subject = X509.X509_Name()
        for n in issuer:
            m2.x509_name_add_entry(subject.x509_name, n.x509_name_entry, -1, 0)
        subject.add_entry_by_txt(field='CN', type=MBSTRING_ASC,
                                 entry=str(self._proxy.get_serial_number()),len=-1, loc=-1, set=0)
        self._proxy.set_dn(subject)
        self._proxy.set_times(lifetime=43200)
        self._proxy.set_issuer_name(self._certificate.get_subject())

        try:
            key_usage = self._certificate._certificate.get_ext('keyUsage')
        except LookupError:
            pass
        else:
            self._proxy.add_extension({'name':key_usage.get_name(),
                                       'critical': key_usage.get_critical(),
                                       'value': self._fix_key_usage(key_usage.get_value())})

        if self._full:
            self._proxy.add_extension({'name':"proxyCertInfo",
                                       'value': PCI_VALUE_FULL,
                                       'critical': 1})
        else:
            self._proxy.add_extension({'name': "proxyCertInfo",
                                           'value': PCI_VALUE_LIMITED,
                                           'critical': 1})

    def _fix_key_usage(self, values):
        """
        invalid values are 'Non Repudiation' and 'keyCertSign'
        digitalSignature is required
        """
        r = []
        for v in values.split(', '):
            if v in ['Non Repudiation', 'keyCertSign']:
                continue
            r.append(v)
        if 'Digital Signature' not in r:
            r.append('Digital Signature')
        return ', '.join(r)


    def set_serial_number(self):
        message_digest = EVP.MessageDigest('sha1')
        pubkey = self._proxy.get_pubkey()
        der_encoding = pubkey.as_der()
        message_digest.update(der_encoding)
        digest = message_digest.final()
        digest_tuple = struct.unpack('BBBB', digest[:4])
        sub_hash = long(digest_tuple[0] + (digest_tuple[1] + ( digest_tuple[2] +
                               ( digest_tuple[3] >> 1) * 256 ) * 256) * 256)
        self._proxy._certificate.set_serial_number(sub_hash)


    def sign(self, md='sha1'):
        self._proxy.sign(self._certificate.get_key(), md)


    def __str__(self):
        return self._proxy.__str__()


    def __repr__(self):
        return self._proxy.__repr__()

    def as_der(self):
        return self._proxy._certificate.as_der()


