package eu.europa.esig.dss.asic.xades;

import eu.europa.esig.dss.definition.DSSElement;
import eu.europa.esig.dss.definition.DSSNamespace;

public enum ManifestElement implements DSSElement {

	MANIFEST("manifest"),

	FILE_ENTRY("file-entry");

	private final DSSNamespace namespace;
	private final String tagName;

	ManifestElement(String tagName) {
		this.tagName = tagName;
		this.namespace = ManifestNamespace.NS;
	}

	@Override
	public DSSNamespace getNamespace() {
		return namespace;
	}

	@Override
	public String getTagName() {
		return tagName;
	}

	@Override
	public String getURI() {
		return namespace.getUri();
	}

	@Override
	public boolean isSameTagName(String value) {
		return tagName.equals(value);
	}

}
