package eu.europa.esig.dss.xades;

import javax.xml.crypto.dsig.XMLSignature;

public class DSSNamespaces {

	public static final DSSNamespace XMLDSIG = new DSSNamespace(XMLSignature.XMLNS, "ds");

	public static final DSSNamespace XADES = new DSSNamespace("http://uri.etsi.org/01903/v1.3.2#", "xades");

	public static final DSSNamespace XADES_141 = new DSSNamespace("http://uri.etsi.org/01903/v1.4.1#", "xades141");

}
