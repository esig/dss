package eu.europa.esig.dss.xades.requirements;

import java.util.Iterator;

import javax.xml.namespace.NamespaceContext;

public class XAdESNamespaceContext implements NamespaceContext {

	@Override
	public String getNamespaceURI(String prefix) {
		if ("xades".equals(prefix)) {
			return "http://uri.etsi.org/01903/v1.3.2#";
		} else if ("xades141".endsWith(prefix)) {
			return "http://uri.etsi.org/01903/v1.4.1#";
		} else if ("ds".equals(prefix)) {
			return "http://www.w3.org/2000/09/xmldsig#";
		}
		//		"http://uri.etsi.org/19132/v1.1.1#"
		return null;
	}

	@Override
	public String getPrefix(String namespaceURI) {
		return null;
	}

	@Override
	public Iterator getPrefixes(String namespaceURI) {
		return null;
	}

}
