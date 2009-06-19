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
from M2Crypto import X509, RSA, EVP, m2
import logging

log = logging.getLogger('arcs.gsi')

MBSTRING_ASC  = 0x1000 | 1

Att_map = {'extendedkeyusage': 'extendedKeyUsage',
           'keyusage': 'keyUsage',
           'certificatepolicies': 'certificatePolicies',
           'subjectaltname': 'subjectAltName',
          }

multi_attrs ={ 'keyusage': { 'digitalsignature' : 'Digital Signature',
                            'keyencipherment' : 'Key Encipherment',
                           }
              , 'extendedkeyusage' : { 'clientauth' : 'clientAuth', }
             }


class Certificate:
    def __init__(self, privateKey=None, publicKey=None,
                 certificateRequest=None, dn=None, extensions=None)

        self.signed = False

        # Generate keys
        log.info('Generating Key')
        if privateKey:
            self._privateKey = privateKey
        else:
            self._privateKey = RSA.gen_key(2048, m2.RSA_F4)

        # Create public key object
        if publicKey:
            self._publicKey = publicKey
        else:
            self._publicKey = EVP.PKey()
        self._publicKey.assign_rsa(self._privateKey)

        # Create certificate request
        if certificateRequest:
            self._certificateRequest = certificateRequest
        else:
            self._certificateRequest = X509.Request()
        self._certificateRequest.set_pubkey(self._publicKey)
        self._certificateRequest.set_version(0)

        if dn:
            self.setDN(dn)

        if extensions:
            self.setExtensions(dn)


    def setDN(self, dn)
        x509Name = X509.X509_Name()
        for entry in dn.split(','):
            l = entry.split("=")
            x509Name.add_entry_by_txt(field=str(l[0].strip()), type=MBSTRING_ASC,
                                          entry=str(l[1]),len=-1, loc=-1, set=0)

        self._certificateRequest.set_subject_name(x509Name)
        self._signed = False


    def setExtensions(self, extensions):
        extstack = X509.X509_Extension_Stack()
        for e in extenstions:
            name = e['name']
            critical = e['critical']
            extstack.push(X509.new_extension(Att_map[name.lower()],
                                             e['value'],
                                             critical=int(critical)))
        self._certificateRequest.add_extensions(extstack)
        self._signed = False


    def sign(self):
        self._certificateRequest.sign(self._publicKey, 'sha1')
        self._signed = True


    def getCertificateRequest(self):
        if not self._signed:
            self.sign()
        return self._certificateRequest


    def getPrivateKey(self):
        return self.privateKey


    def getPublicKey(self):
        return self.publicKey


