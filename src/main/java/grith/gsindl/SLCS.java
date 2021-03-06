package grith.gsindl;

import grisu.jcommons.interfaces.SlcsListener;
import grith.sibboleth.CredentialManager;
import grith.sibboleth.IdpObject;
import grith.sibboleth.ShibListener;
import grith.sibboleth.ShibLoginEventSource;
import grith.sibboleth.Shibboleth;
import grith.sibboleth.StaticCredentialManager;
import grith.sibboleth.StaticIdpObject;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Vector;

import org.apache.commons.lang.StringUtils;
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
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.python.core.PyDictionary;
import org.python.core.PyInstance;
import org.python.core.PyList;
import org.python.core.PyObject;
import org.python.core.PyString;
import org.python.util.PythonInterpreter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableCollection;
import com.google.common.collect.ImmutableList;




public class SLCS implements ShibListener {

	static final Logger myLogger = LoggerFactory.getLogger(SLCS.class.getName());

//	public static final String DEFAULT_SLCS_URL = "https://slcs1.arcs.org.au/Shibboleth.sso/DS?discoveryURL=https://directory.tuakiri.ac.nz/TuakiriAAF-discovery/DS&target=https://slcs1.arcs.org.au/SLCS/login";
	public static final String DEFAULT_SLCS_URL = "https://slcs1.nesi.org.nz/SLCS/login";
	
	public static void main(String[] args) throws IOException,
	KeyStoreException, NoSuchAlgorithmException, CertificateException {

		// optional
		Shibboleth.initDefaultSecurityProvider();

		final String idp = "The University of Auckland";
		final String username = "mbin029";
		// I know, the password should be a char[]. But that doesn't work with
		// the jython bindings and it would be useless in
		// this case anyway since python uses plain strings in memory.
		final char[] password = args[0].toCharArray();

		IdpObject idpObject = new StaticIdpObject(idp);
		CredentialManager cm = new StaticCredentialManager(username, password);

		Shibboleth shibboleth = new Shibboleth(idpObject, cm);
		shibboleth.openurl(DEFAULT_SLCS_URL);
		
		String response = shibboleth.getResponseAsString();
//		System.out.println(response);
//
//		SLCS slcs = new SLCS(shibboleth);
//		slcs.shibLoginComplete(shibboleth.getResponse());
		
		SLCS slcs = new SLCS(response);

		// get the certificate & key
		X509Certificate cert = slcs.getCertificate();
		PrivateKey privateKey = slcs.getPrivateKey();
		
		File privateKeyFile = new File("/home/markus/key.pem");

		X509Certificate[] certChain = new X509Certificate[1];
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("PKCS12", "BC");
			ks.load(null, null);
			certChain[0] = cert;
		} catch (Exception e) {
			myLogger.error(e.getLocalizedMessage());
		}

		File p12file = new File("/home/markus/cert.p12");
		OutputStream fos = null;

		ks.setKeyEntry("Markus Binsteiner", privateKey, null, certChain);
		fos = new FileOutputStream(p12file);
		ks.store(fos, "nnnn".toCharArray());
		try {
			fos.close();
		} catch (Exception e) {
			myLogger.error(e.getLocalizedMessage());
		}

	}

	private final PythonInterpreter interpreter = new PythonInterpreter();

	private KeyPairGenerator kpGen = null;
	private PrivateKey privateKey = null;

	private X509Certificate x509Cert = null;

	private PyInstance response;
	private String responseString;
	
	// Event stuff
	private Vector<SlcsListener> slcsListeners;

	public SLCS(ShibLoginEventSource shibEventSource) {
		initSecurityStuff();

		// fix for webstart
		interpreter.exec("import sys");
		interpreter.exec("sys.prefix = ''");
		shibEventSource.addShibListener(this);
	}

	public SLCS(String url, IdpObject idp, CredentialManager cm) {

		initSecurityStuff();

		// fix for webstart
		interpreter.exec("import sys");
		interpreter.exec("sys.prefix = ''");
		// interpreter.exec("sys.add_package('grith.sibboleth')");
		// interpreter.exec("sys.add_package('grith.gsindl')");

		Shibboleth shib = new Shibboleth(idp, cm);
		shib.addShibListener(this);
		shib.openurl(url);
	}
	
	public SLCS(String serverResponse, Collection<SlcsListener> listeners) {
		initSecurityStuff();
		
		if ( listeners != null ) {
		for ( SlcsListener l : listeners ) {
			addSlcsListener(l);
		}
		}
		// fix for webstart
		interpreter.exec("import sys");
		interpreter.exec("sys.prefix = ''");
		
		this.responseString = serverResponse;
		startSlcsRequest();
	}
	
	public SLCS(String serverResponse, SlcsListener listener) {
		this(serverResponse, ImmutableList.of(listener));
	}
	
	public SLCS(String serverResponse) {
		this(serverResponse, (Collection<SlcsListener>)null);
	}

	// register a listener
	synchronized public void addSlcsListener(SlcsListener l) {
		if (slcsListeners == null) {
			slcsListeners = new Vector<SlcsListener>();
		}
		slcsListeners.addElement(l);
	}
	

	private String createCertificateRequest(Object response) {

		interpreter.exec("from gsindl.slcs import parse_req_response");

		interpreter.set("slcsResp", response);
		interpreter
		.exec("token, dn, reqURL, elements = parse_req_response(slcsResp)");

		PyString dn = (PyString) interpreter.get("dn");
		// PyUnicode reqUrl = (PyUnicode)interpreter.get("reqURL");
		// PyString token = (PyString)interpreter.get("token");
		PyList elObjects = (PyList) interpreter.get("elements");

		PyDictionary[] elements = new PyDictionary[elObjects.size()];

		for (int i = 0; i < elements.length; i++) {
			elements[i] = (PyDictionary) elObjects.get(i);
		}

		try {

			KeyPair pair = null;
			pair = kpGen.generateKeyPair();

			Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
			Vector<X509Extension> values = new Vector<X509Extension>();

			for (PyDictionary dic : elements) {

				String name = null;
				String oid = null;
				boolean critical = false;
				String value = null;

				for (Object keyO : dic.keys()) {
					String key = (String) keyO;

					if ("oid".equals(key)) {
						oid = (String) dic.get(key);
					} else if ("name".equals(key)) {
						name = (String) dic.get(key);
					} else if ("critical".equals(key)) {
						critical = (Boolean) dic.get(key);
					} else if ("value".equals(key)) {
						value = (String) dic.get(key);
					} else {
						throw new RuntimeException("Can't match key: " + key);
					}
				}

				// System.out.println("Set: ");
				// System.out.println("\tname: "+name);
				// System.out.println("\toid: "+oid);
				// System.out.println("\tcritical: "+critical);
				// System.out.println("\tvalue: "+value);

				if ("SubjectAltName".equals(name)) {
					String email = value.substring(value.indexOf(":") + 1);
					GeneralNames subjectAltName = new GeneralNames(
							new GeneralName(GeneralName.rfc822Name, email));
					oids.add(X509Extensions.SubjectAlternativeName);
					values.add(new X509Extension(critical, new DEROctetString(
							subjectAltName)));

				} else if ("ExtendedKeyUsage".equals(name)) {

					ExtendedKeyUsage extendedKeyUsage = null;
					if ("ClientAuth".equals(value)) {
						extendedKeyUsage = new ExtendedKeyUsage(
								KeyPurposeId.id_kp_clientAuth);
					} else {
						throw new RuntimeException("ExtendedKeyUsage: " + value
								+ " not implemented!");
					}
					X509Extension extension = new X509Extension(critical,
							new DEROctetString(extendedKeyUsage));

					oids.add(X509Extensions.ExtendedKeyUsage);
					values.add(extension);

				} else if ("KeyUsage".equals(name)) {

					KeyUsage keyUsage = null;
					if ("DigitalSignature,KeyEncipherment".equals(value)) {
						keyUsage = new KeyUsage(KeyUsage.digitalSignature
								| KeyUsage.keyEncipherment);
					} else {
						throw new RuntimeException("KeyUsage: " + value
								+ " not implemented!");
					}
					X509Extension extension = new X509Extension(critical,
							new DEROctetString(keyUsage));
					oids.add(X509Extensions.KeyUsage);
					values.add(extension);

				} else if ("CertificatePolicies".equals(name)) {

					CertificatePolicies certPolicies = null;
					if ("1.3.6.1.4.1.31863.1.0.1".equals(value)) {
						certPolicies = new CertificatePolicies(value);
					} else {
						throw new RuntimeException("CertificatePolicies: "
								+ value + " not implemented!");
					}
					X509Extension extension = new X509Extension(critical,
							new DEROctetString(certPolicies));
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
					new X509Name(false, dn.asString()), pair.getPublic(),
					new DERSet(attribute), pair.getPrivate());

			// System.out.println(certRequest.getCertificationRequestInfo().getSubject().toString());

			StringWriter writer = new StringWriter();
			PEMWriter pemWrt = new PEMWriter(writer);
			pemWrt.writeObject(certRequest);
			pemWrt.close();

			writer.close();

			// persist the private key
			privateKey = pair.getPrivate();

			return writer.toString();

		} catch (Exception e) {
			throw new RuntimeException("Could not create certificate request.",
					e);
		}
	}

	private void fireNewSlcsCert(boolean failed, Exception optionalException) {

		if ((slcsListeners != null) && !slcsListeners.isEmpty()) {

			// make a copy of the listener list in case
			// anyone adds/removes mountPointsListeners
			Vector<SlcsListener> slcsChangeTargets;
			synchronized (this) {
				slcsChangeTargets = (Vector<SlcsListener>) slcsListeners
						.clone();
			}

			// walk through the listener list and
			// call the gridproxychanged method in each
			Enumeration<SlcsListener> e = slcsChangeTargets.elements();
			while (e.hasMoreElements()) {
				SlcsListener valueChanged_l = e.nextElement();
				if (failed) {
					valueChanged_l.slcsLoginFailed(
							"Could not generate slcs certificate/proxy.",
							optionalException);
				} else {
					valueChanged_l.slcsLoginComplete(getCertificate(),
							getPrivateKey());
				}
			}
		}
	}

	public X509Certificate getCertificate() {
		return x509Cert;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void initSecurityStuff() {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		try {
			kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		} catch (NoSuchAlgorithmException e) {
			myLogger.error(
					"Can't init security environment: "
							+ e.getLocalizedMessage(), e);
		} catch (NoSuchProviderException e) {
			myLogger.error(
					"Can't init Security environemtn: "
							+ e.getLocalizedMessage(), e);
		}

		kpGen.initialize(1024, new SecureRandom());

	}

	// remove a listener
	synchronized public void removeSlcsListener(SlcsListener l) {
		if (slcsListeners == null) {
			slcsListeners = new Vector<SlcsListener>();
		}
		slcsListeners.removeElement(l);
	}

	public void shibLoginComplete(PyInstance response) {

		this.response = response;

		startSlcsRequest();

	}

	public void shibLoginFailed(Exception e) {

		// do nothing...

	}

	public void shibLoginStarted() {

		// do nothing

	}

	private void startSlcsRequest() {

		try {
			String pem;
			if ( StringUtils.isNotBlank(this.responseString) ) {
				pem = createCertificateRequest(this.responseString);
			} else {
				pem = createCertificateRequest(response);
			}

			String cert = submitCertificateRequest(pem);

			x509Cert = (X509Certificate) CertificateFactory.getInstance(
					"X.509", "BC").generateCertificate(
							new ByteArrayInputStream(cert.getBytes()));
		} catch (Exception e) {
			fireNewSlcsCert(true, e);
			return;
		}

		fireNewSlcsCert(false, null);
	}

	private String submitCertificateRequest(String pem) {

		interpreter.set("certreq", pem);
		interpreter.exec("from urllib import urlencode");
		interpreter.exec("import urllib2");
		interpreter
		.exec("data = urlencode({'AuthorizationToken': token,'CertificateSigningRequest': certreq})");
		interpreter.exec("certResp = urllib2.urlopen(reqURL, data)");

		interpreter.exec("from gsindl.slcs import parse_cert_response");
		interpreter.exec("cert = parse_cert_response(certResp)");

		PyObject cert = interpreter.get("cert");

		return cert.asString();

	}
}
