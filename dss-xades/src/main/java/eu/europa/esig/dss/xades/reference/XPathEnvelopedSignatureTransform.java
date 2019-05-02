package eu.europa.esig.dss.xades.reference;

public final class XPathEnvelopedSignatureTransform extends XPathTransform {

	/**
	 * This XPath filter allows to remove all ds:Signature elements from the XML
	 */
	private static final String NOT_ANCESTOR_OR_SELF_DS_SIGNATURE = "not(ancestor-or-self::ds:Signature)";

	public XPathEnvelopedSignatureTransform() {
		super(NOT_ANCESTOR_OR_SELF_DS_SIGNATURE);
	}

}
