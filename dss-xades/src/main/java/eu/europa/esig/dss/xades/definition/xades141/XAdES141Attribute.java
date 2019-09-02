package eu.europa.esig.dss.xades.definition.xades141;

import eu.europa.esig.dss.xades.definition.DSSAttribute;

public enum XAdES141Attribute implements DSSAttribute {

	ID("Id"),

	ORDER("Order"),

	URI("URI");

	private final String attributeName;

	XAdES141Attribute(String attributeName) {
		this.attributeName = attributeName;
	}

	@Override
	public String getAttributeName() {
		return attributeName;
	}

}
