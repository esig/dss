package eu.europa.esig.dss.xades.reference;

public final class XPath2FilterEnvelopedSignatureTransform extends XPath2FilterTransform {
	
	private static final String SUBTRACT_FILTER = "subtract";
	
	private static final String DESCENDANT_SIGNATURE = "/descendant::ds:Signature";

	public XPath2FilterEnvelopedSignatureTransform() {
		super(DESCENDANT_SIGNATURE, SUBTRACT_FILTER);
	}

}
