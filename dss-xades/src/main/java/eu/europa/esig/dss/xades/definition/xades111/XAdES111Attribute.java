package eu.europa.esig.dss.xades.definition.xades111;

import eu.europa.esig.dss.xades.definition.DSSAttribute;

public enum XAdES111Attribute implements DSSAttribute {

	ID("Id"),

	OBJECT_REFERENCE("ObjectReference"),

	QUALIFIER("Qualifier"),

	TARGET("Target"),

	URI("uri"),

	URI2("URI");

	private final String attributeName;

	XAdES111Attribute(String attributeName) {
		this.attributeName = attributeName;
	}

	@Override
	public String getAttributeName() {
		return attributeName;
	}

}
