package au.org.arcs.auth.slcs;

import java.util.Iterator;

import org.python.core.PyInstance;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;

import au.org.arcs.auth.shibboleth.ArcsSecurityProvider;
import au.org.arcs.auth.shibboleth.Shibboleth;

public class SLCS {
	
	PythonInterpreter interpreter = new PythonInterpreter();
	
	
	public SLCS() {
	}
	
	
	public Object parse_req_response(PyInstance response) {
		
        interpreter.exec("import arcs.gsi.slcs");
//        interpreter.eval(s)
        PyObject shibbolethClientClass = interpreter.get("slcs");
        PyObject employeeObj = shibbolethClientClass.__call__();	
		
		return null;
	}
	
	
	public static void main(String[] args) {
		
    	java.security.Security.addProvider(new ArcsSecurityProvider());

    	java.security.Security.setProperty("ssl.TrustManagerFactory.algorithm", "TrustAllCertificates");
    	
    	Shibboleth shib = new Shibboleth("https://slcs1.arcs.org.au/SLCS/login");
    	
    	PyInstance returnValue = shib.shibOpen(args[0], args[1].toCharArray(), "VPAC");
    	
    	Iterable<PyObject> it = returnValue.asIterable();
    	
    	for ( Iterator i = it.iterator(); i.hasNext(); ) {
    		
    		System.out.println(i.next());
    		
    	}
    	
    	returnValue = shib.open();
    	
    	it = returnValue.asIterable();
    	
    	for ( Iterator i = it.iterator(); i.hasNext(); ) {
    		
    		System.out.println(i.next());
    		
    	}
		
		
	}

}
