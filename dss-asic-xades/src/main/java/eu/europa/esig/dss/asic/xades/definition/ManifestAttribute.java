package eu.europa.esig.dss.asic.xades.definition;

import eu.europa.esig.dss.definition.DSSAttribute;

public enum ManifestAttribute implements DSSAttribute {

	VERSION("version"),

	FULL_PATH("full-path"),

	MEDIA_TYPE("media-type");

	private final String attributeName;

	ManifestAttribute(String attributeName) {
		this.attributeName = attributeName;
	}

	@Override
	public String getAttributeName() {
		return attributeName;
	}

}
