package eu.europa.esig.dss.asic.common.definition;

import eu.europa.esig.dss.definition.DSSAttribute;

public enum ASiCAttribute implements DSSAttribute {

	URI("URI"),

	MIME_TYPE("MimeType"),

	ROOTFILE("Rootfile"),
	
	CRITICAL("Critical");
	
	private final String attributeName;

	ASiCAttribute(String attributeName) {
		this.attributeName = attributeName;
	}

	@Override
	public String getAttributeName() {
		return attributeName;
	}

}
