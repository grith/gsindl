Introduction
============

This library provides some utility classes and functions for deailing with X509 certificates. Most of the tasks performed by these classes are trivial but they require use of the M2Crypto classes which can be a pain. The problem isn't that the M2Crypto classes are complex, it just that when doing GSI tasks i find myself repeating work in different projects.

>>> import arcs.gsi.certificate
>>> r = arcs.gsi.certificate.CertificateRequest()
>>> r.set_dn("DC=au,DC=org,DC=arcs,DC=test,O=VPAC,CN=Russell Sim")
>>> r.sign()
>>> print r.get_cert_req().as_text()
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: DC=au, DC=org, DC=arcs, DC=test, O=VPAC, CN=Russell Sim
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    ...
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha1WithRSAEncryption
        ...
<BLANKLINE>

Generating a request with a 1024 bit key for compatablity with older applications.

>>> r = arcs.gsi.certificate.CertificateRequest(dn="DC=au,DC=org,DC=arcs,DC=test,O=VPAC,CN=Russell Sim", keySize=1024)
>>> r.sign()
>>> print r
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: DC=au, DC=org, DC=arcs, DC=test, O=VPAC, CN=Russell Sim
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (1024 bit)
                Modulus (1024 bit):
                    ...
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha1WithRSAEncryption
        ...
<BLANKLINE>

It's easier to access a certificate without needing to introspect M2Crypto to figure out the calls.

>>> r
-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----
<BLANKLINE>

>>> r = arcs.gsi.certificate.CertificateRequest(dn="DC=au,DC=org,DC=arcs,DC=test,O=VPAC,CN=Russell Sim", keySize=1024)

Extensions are passed in as a list of dictionarys.

>>> r.add_extensions([{'critical': False, 'name': 'ExtendedKeyUsage', 'value': 'clientAuth'}, {'critical': True, 'name': 'KeyUsage', 'value': 'Digital Signature, Key Encipherment'}, {'critical': False, 'name': 'CertificatePolicies', 'value': '1.3.6.1.4.1.31863.1.0.1'}, {'critical': False, 'name': 'SubjectAltName', 'value': 'email:russell@vpac.org'}])
>>> r.sign()
>>> print r
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: DC=au, DC=org, DC=arcs, DC=test, O=VPAC, CN=Russell Sim
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (1024 bit)
                Modulus (1024 bit):
                ...
                Exponent: 65537 (0x10001)
        Attributes:
        Requested Extensions:
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Certificate Policies: 
                Policy: 1.3.6.1.4.1.31863.1.0.1
<BLANKLINE>
            X509v3 Subject Alternative Name: 
                email:russell@vpac.org
    Signature Algorithm: sha1WithRSAEncryption
    ...
<BLANKLINE>

Creating certificates
---------------------

Creating a certificate, currently this can't be done from a request because there are no methods to extract the extensions from a request.

>>> c = arcs.gsi.certificate.Certificate()
>>> c.set_dn("DC=au,DC=org,DC=arcs,DC=test,O=VPAC,CN=Russell Sim")
>>> c.add_extensions([{'critical': False, 'name': 'ExtendedKeyUsage', 'value': 'clientAuth'}, {'critical': True, 'name': 'KeyUsage', 'value': 'Digital Signature, Key Encipherment'}, {'critical': False, 'name': 'CertificatePolicies', 'value': '1.3.6.1.4.1.31863.1.0.1'}, {'critical': False, 'name': 'SubjectAltName', 'value': 'email:russell@vpac.org'}])
>>> c.set_version(2)
>>> c.set_serial_number()
>>> c.set_times()
>>> c.set_issuer_name(c.get_subject())
>>> k = arcs.gsi.key.Key()
>>> c.sign(k)

Creating a proxy certificate
----------------------------

>>> p = arcs.gsi.proxy.ProxyCertificate(c)
>>> p.sign()
>>> print p
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: ... (0x...)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: DC=au, DC=org, DC=arcs, DC=test, O=VPAC, CN=Russell Sim
        Validity
            Not Before: ...
            Not After : ...
        Subject: DC=au, DC=org, DC=arcs, DC=test, O=VPAC, CN=Russell Sim, CN=...
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Data Encipherment
            Proxy Certificate Information: critical
                Path Length Constraint: infinite
                Policy Language: Inherit all
<BLANKLINE>
    Signature Algorithm: sha1WithRSAEncryption
        ...
<BLANKLINE>




