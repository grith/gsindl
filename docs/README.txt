Introduction
============

This library provides some utility classes and functions for deailing with X509 certificates. Most of the tasks performed by these classes are trivial but they require use of the M2Crypto classes which can be a pain.

>>> import arcs.gsi.certificate
>>> c = arcs.gsi.certificate.CertificateRequest()
>>> c.setDN("DC=au,DC=org,DC=arcs,DC=test,O=VPAC,CN=Russell Sim")
>>> print c.getCertificateRequest().as_text()
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

>>> c = arcs.gsi.certificate.CertificateRequest(dn="DC=au,DC=org,DC=arcs,DC=test,O=VPAC,CN=Russell Sim", keySize=1024)
>>> print c
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
>>> c
-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----
<BLANKLINE>


