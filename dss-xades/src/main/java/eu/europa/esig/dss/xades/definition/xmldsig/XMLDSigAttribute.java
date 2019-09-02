package eu.europa.esig.dss.xades.definition.xmldsig;

import eu.europa.esig.dss.xades.definition.DSSAttribute;

public enum XMLDSigAttribute implements DSSAttribute {

	ALGORITHM("Algorithm"),

	ENCODING("Encoding"),

	ID("Id"),

	MIME_TYPE("MimeType"),

	TARGET("Target"),

	TYPE("Type"),

	URI("URI");

	private final String attributeName;

	XMLDSigAttribute(String attributeName) {
		this.attributeName = attributeName;
	}

	@Override
	public String getAttributeName() {
		return attributeName;
	}

}
