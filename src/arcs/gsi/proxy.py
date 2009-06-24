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

from certificate import Certificate
from key import Key


PCI_VALUE_FULL = "critical, language:Inherit all"
PCI_VALUE_LIMITED = "critical, language:1.3.6.1.4.1.3536.1.1.1.9"


class ProxyCertificate:
    def __init__(self, certificate, full=True):
        if isinstance(certificate, Certificate):
            self._certificate = certificate
        else:
            self._certificate = Certificate(certificate)
        self._full = full

        self._proxy = Certificate()

        self._proxy.set_version(2)
        self._proxy.set_serial_number()
        self._proxy.set_dn(self._certificate.get_subject().as_text() + ', CN=' + str(self._proxy.get_serial_number()))
        self._proxy.set_times()
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
            self._proxycert.add_extension({'name': "proxyCertInfo",
                                           'value': PCI_VALUE_LIMITED,
                                           'critical': 1})
        return

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
        if 'Data Encipherment' not in r:
            r.append('Data Encipherment')
        return ', '.join(r)


    def sign(self, md='sha1'):
        self._proxy.sign(self._certificate.get_key(), md)


    def __str__(self):
        return self._proxy.__str__()


    def __repr__(self):
        return self._proxy.__repr__()


