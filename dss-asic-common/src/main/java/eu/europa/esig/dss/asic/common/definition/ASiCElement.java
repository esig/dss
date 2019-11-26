package eu.europa.esig.dss.asic.common.definition;

import eu.europa.esig.dss.definition.DSSElement;
import eu.europa.esig.dss.definition.DSSNamespace;

public enum ASiCElement implements DSSElement {

	XADES_SIGNATURES("XAdESSignatures"),

	ASIC_MANIFEST("ASiCManifest"),

	SIG_REFERENCE("SigReference"),
	
	EXTENSION("Extension"),

	DATA_OBJECT_REFERENCE("DataObjectReference"),
	
	ASIC_MANIFEST_EXTENSIONS("ASiCManifestExtensions"),
	
	DATA_OBJECT_REFERENCE_EXTENSIONS("DataObjectReferenceExtensions");

	private final DSSNamespace namespace;
	private final String tagName;

	ASiCElement(String tagName) {
		this.tagName = tagName;
		this.namespace = ASiCNamespace.NS;
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
