package eu.europa.esig.dss.xades.definition;

import javax.xml.crypto.dsig.XMLSignature;

public class DSSNamespaces {

	public static final DSSNamespace XMLDSIG = new DSSNamespace(XMLSignature.XMLNS, "ds");

	public static final DSSNamespace XADES_111 = new DSSNamespace("http://uri.etsi.org/01903/v1.1.1#", "xades111");
	public static final DSSNamespace XADES_122 = new DSSNamespace("http://uri.etsi.org/01903/v1.2.2#", "xades122");
	public static final DSSNamespace XADES_132 = new DSSNamespace("http://uri.etsi.org/01903/v1.3.2#", "xades132");
	public static final DSSNamespace XADES_141 = new DSSNamespace("http://uri.etsi.org/01903/v1.4.1#", "xades141");

}
