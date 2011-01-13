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
import struct

from M2Crypto import EVP, m2, X509, ASN1

from gsindl.certificate import generate_certificate, multi_attrs, Att_map

MBSTRING_ASC = 0x1000 | 1
PCI_VALUE_FULL = "critical, language:Inherit all"
PCI_VALUE_LIMITED = "critical, language:1.3.6.1.4.1.3536.1.1.1.9"


def generate_proxy(certificate, proxykey=None, full=True,
                   lifetime=43200, extensions=[]):
    """
    generate a new proxy certificate

    :param certificate: the parent certificate
    :param proxykey: the key used to sign the proxy
    :param full: whether this is a full proxy or not
    """
    _certificate = certificate
    _full = full

    _proxy, _key = generate_certificate(key=proxykey)

    _proxy.set_version(2)

    # generate serial
    message_digest = EVP.MessageDigest('sha1')
    pubkey = _proxy.get_pubkey()
    der_encoding = pubkey.as_der()
    message_digest.update(der_encoding)
    digest = message_digest.final()
    digest_tuple = struct.unpack('BBBB', digest[:4])
    sub_hash = long(digest_tuple[0] +
                    (digest_tuple[1] +
                     (digest_tuple[2] +
                       (digest_tuple[3] >> 1) * 256) * 256) * 256)
    _proxy.set_serial_number(sub_hash)

    # set issuer
    issuer = _certificate.get_subject()

    # set subject
    subject = X509.X509_Name()
    for n in issuer:
        m2.x509_name_add_entry(subject.x509_name, n.x509_name_entry, -1, 0)
    subject.add_entry_by_txt(field='CN', type=MBSTRING_ASC,
                             entry=str(_proxy.get_serial_number()),
                             len=-1, loc=-1, set=0)
    _proxy.set_subject_name(subject)

    # set times
    not_before = ASN1.ASN1_UTCTIME()
    not_after = ASN1.ASN1_UTCTIME()
    not_before.set_time(int(time.time()) - 300)
    not_after.set_time(int(time.time()) + lifetime)
    _proxy.set_not_before(not_before)
    _proxy.set_not_after(not_after)

    _proxy.set_issuer_name(_certificate.get_subject())

    # add extensions
    try:
        key_usage = _certificate.get_ext('keyUsage')
    except LookupError:
        pass
    else:
        r = []
        for v in key_usage.get_value().split(', '):
            if v in ['Non Repudiation', 'keyCertSign']:
                continue
            r.append(v)
        if 'Digital Signature' not in r:
            r.append('Digital Signature')
        key_usage_value = ', '.join(r)
        extensions.append({'name': key_usage.get_name(),
                           'critical': key_usage.get_critical(),
                           'value': key_usage_value})

    if _full:
        extensions.append({'name': "proxyCertInfo",
                           'value': PCI_VALUE_FULL,
                           'critical': 1})
    else:
        extensions.append({'name': "proxyCertInfo",
                           'value': PCI_VALUE_LIMITED,
                           'critical': 1})
    if extensions:
        sslower = lambda s: s.lower().replace(' ', '')

        for e in extensions:
            name = e['name']
            key = sslower(name)
            critical = e['critical']
            if key in multi_attrs:
                e['value'] = ', '.join([multi_attrs[key][sslower(v)]
                               for v in e['value'].split(',')])
            _proxy.add_ext(X509.new_extension(Att_map[key],
                                              e['value'],
                                              critical=int(critical)))

    return _proxy, _key
