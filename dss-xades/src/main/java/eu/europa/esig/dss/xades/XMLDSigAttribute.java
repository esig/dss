package eu.europa.esig.dss.xades;

public enum XMLDSigAttribute implements DSSAttribute {

	ID("Id"),

	ALGORITHM("Algorithm"),

	URI("URI"),

	TYPE("Type"),

	MIME_TYPE("MimeType"),

	ENCODING("Encoding"),

	TARGET("Target");

	private final String attributeName;

	XMLDSigAttribute(String attributeName) {
		this.attributeName = attributeName;
	}

	@Override
	public String getAttributeName() {
		return attributeName;
	}

}
