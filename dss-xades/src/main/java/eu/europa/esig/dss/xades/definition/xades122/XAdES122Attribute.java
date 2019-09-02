package eu.europa.esig.dss.xades.definition.xades122;

import eu.europa.esig.dss.xades.definition.DSSAttribute;

public enum XAdES122Attribute implements DSSAttribute {

	ID("Id"),

	OBJECT_REFERENCE("ObjectReference"),

	QUALIFIER("Qualifier"),

	REFERENCED_DATA("referencedData"),

	TARGET("Target"),

	URI("URI");

	private final String attributeName;

	XAdES122Attribute(String attributeName) {
		this.attributeName = attributeName;
	}

	@Override
	public String getAttributeName() {
		return attributeName;
	}

}
