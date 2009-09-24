package au.org.arcs.auth.slcs;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface SlcsListener {
	
	public void slcsLoginComplete(X509Certificate cert, PrivateKey privateKey);

}
