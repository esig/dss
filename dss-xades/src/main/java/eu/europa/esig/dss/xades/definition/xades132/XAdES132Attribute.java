package eu.europa.esig.dss.xades.definition.xades132;

import eu.europa.esig.dss.xades.definition.DSSAttribute;

public enum XAdES132Attribute implements DSSAttribute {

	ENCODING("Encoding"),

	ID("Id"),

	OBJECT_REFERENCE("ObjectReference"),

	QUALIFIER("Qualifier"),

	REFERENCED_DATA("referencedData"),

	TARGET("Target"),

	URI("URI");

	private final String attributeName;

	XAdES132Attribute(String attributeName) {
		this.attributeName = attributeName;
	}

	public String getAttributeName() {
		return attributeName;
	}

}
