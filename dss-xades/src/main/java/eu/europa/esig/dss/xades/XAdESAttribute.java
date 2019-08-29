package eu.europa.esig.dss.xades;

public enum XAdESAttribute implements DSSAttribute {

	ID("Id"),

	URI("URI"),

	REFERENCED_DATA("referencedData"),

	ENCODING("Encoding"),

	QUALIFIER("Qualifier"),

	OBJECT_REFERENCE("ObjectReference"),

	TARGET("Target");

	private final String attributeName;

	XAdESAttribute(String attributeName) {
		this.attributeName = attributeName;
	}

	public String getAttributeName() {
		return attributeName;
	}

}
