package au.org.arcs.auth.slcs;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.python.core.PyDictionary;
import org.python.core.PyInstance;
import org.python.core.PyList;
import org.python.core.PyString;
import org.python.core.PyUnicode;
import org.python.util.PythonInterpreter;

import au.org.arcs.auth.shibboleth.ArcsSecurityProvider;
import au.org.arcs.auth.shibboleth.Shibboleth;

public class SLCS {

	private PythonInterpreter interpreter = new PythonInterpreter();
	private KeyPairGenerator kpGen = null;

	public SLCS() {

		Security
				.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try {
			kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		kpGen.initialize(1024, new SecureRandom());

	}

	public String createCertificateRequest(PyInstance response) {

		interpreter.exec("from arcs.gsi.slcs import parse_req_response");

		interpreter.set("slcsResp", response);
		interpreter
				.exec("token, dn, reqURL, elements = parse_req_response(slcsResp)");

		PyString token = (PyString)interpreter.get("token");
		PyString dn = (PyString)interpreter.get("dn");
		PyUnicode reqUrl = (PyUnicode)interpreter.get("reqURL");
		PyList elObjects = (PyList)interpreter.get("elements");
		
		PyDictionary[] elements = new PyDictionary[elObjects.size()];
		
		for ( int i=0; i<elements.length; i++ ) {
			elements[i] = (PyDictionary)elObjects.get(i);
		}

		try {
			KeyPair pair = kpGen.generateKeyPair();


			Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
			Vector values = new Vector();

//			GeneralNames subjectAltName = new GeneralNames(new GeneralName(
//					GeneralName.rfc822Name, "test@test.test"));
//
//			oids.add(X509Extensions.SubjectAlternativeName);
//			values.add(new X509Extension(false, new DEROctetString(
//					subjectAltName)));
			
//			ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
			
			for ( PyDictionary dic : elements ) {
				
				String name = null;
				String oid = null;
				boolean critical = false;
				String value = null;
				
				for ( Object keyO : dic.keys() ) {
					String key = (String)keyO;
					
					if ( "oid".equals(key) ) {
						oid = (String)dic.get(key);
					} else if ( "name".equals(key) ) {
						name = (String)dic.get(key);
					} else if ( "critical".equals(key) ) {
						critical = (Boolean)dic.get(key);
					} else if ( "value".equals(key) ) {
						value = (String)dic.get(key);
					} else {
						throw new RuntimeException("Can't match key: "+key);
					}
				}
				
				
				System.out.println("Set: ");
				System.out.println("\tname: "+name);
				System.out.println("\toid: "+oid);
				System.out.println("\tcritical: "+critical);
				System.out.println("\tvalue: "+value);
				
				if ( "SubjectAltName".equals(name) ) {
					
					GeneralNames subjectAltName = new GeneralNames(
			                   new GeneralName(GeneralName.rfc822Name, value));
					oids.add(X509Extensions.SubjectAlternativeName);
					values.add(new X509Extension(critical, new DEROctetString(subjectAltName)));
					
				} else if ( "ExtendedKeyUsage".equals(name) ) {
					
					ExtendedKeyUsage extendedKeyUsage = null;
					if ( "ClientAuth".equals(value) ) {
						extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
					} else {
						throw new RuntimeException("ExtendedKeyUsage: "+value+" not implemented!");
					}
					X509Extension extension = new X509Extension(critical, new DEROctetString(extendedKeyUsage));

					oids.add(X509Extensions.ExtendedKeyUsage);
					values.add(extension);
					
				} else if ( "KeyUsage".equals(name) ) {
					
					KeyUsage keyUsage = null;
					if ( "DigitalSignature,KeyEncipherment".equals(value) ) {
						keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
					} else {
						throw new RuntimeException("KeyUsage: "+value+" not implemented!");
					}
					X509Extension extension = new X509Extension(critical, new DEROctetString(keyUsage));
					oids.add(X509Extensions.KeyUsage);
					values.add(extension);
					
				} else if ( "CertificatePolicies".equals(name) ) {
					
					CertificatePolicies certPolicies = null;
					if ( "1.3.6.1.4.1.31863.1.0.1".equals(value) ) {
						certPolicies = new CertificatePolicies(value);
					} else {
						throw new RuntimeException("CertificatePolicies: "+value+" not implemented!");
					}
					X509Extension extension = new X509Extension(critical, new DEROctetString(certPolicies));
					oids.add(X509Extensions.CertificatePolicies);
					values.add(extension);
				}
				
			}

			X509Extensions extensions = new X509Extensions(oids, values);

			Attribute attribute = new Attribute(
					PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
					new DERSet(extensions));

			PKCS10CertificationRequest certRequest = null;
			certRequest = new PKCS10CertificationRequest("SHA256withRSA",
					new X500Principal(dn.asString()), pair
							.getPublic(), new DERSet(attribute), pair
							.getPrivate());

			StringWriter writer = new StringWriter();
			PEMWriter pemWrt = new PEMWriter(writer);
			pemWrt.writeObject(certRequest);
			pemWrt.close();
			
			writer.close();
			
			return writer.toString();

		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}

	public static void main(String[] args) {

		java.security.Security.addProvider(new ArcsSecurityProvider());

		java.security.Security.setProperty("ssl.TrustManagerFactory.algorithm",
				"TrustAllCertificates");

		Shibboleth shib = new Shibboleth("https://slcs1.arcs.org.au/SLCS/login");

		PyInstance returnValue = shib.shibOpen(args[0], args[1].toCharArray(),
				"VPAC");

		SLCS slcs = new SLCS();

		String pem = slcs.createCertificateRequest(returnValue);
		
		System.out.println(pem);

//		Iterable<PyObject> it = returnValue.asIterable();
//
//		for (Iterator i = it.iterator(); i.hasNext();) {
//
//			System.out.println(i.next());
//
//		}
//
//		returnValue = shib.open();
//
//		it = returnValue.asIterable();
//
//		for (Iterator i = it.iterator(); i.hasNext();) {
//
//			System.out.println(i.next());
//
//		}

	}

}
