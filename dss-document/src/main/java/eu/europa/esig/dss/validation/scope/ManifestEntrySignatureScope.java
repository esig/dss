package eu.europa.esig.dss.validation.scope;

import java.util.List;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.SignatureScopeType;

public class ManifestEntrySignatureScope extends SignatureScopeWithTransformations {
	
	private final String manifestName;

	/**
	 * Constructor with transformations (Used in XAdES)
	 * @param entryName {@link String} name of the manifest entry
	 * @param digest {@link Digest} of the manifest entry
	 * @param manifestName {@link String} name of the manifest containing the entry
	 * @param transformations list of {@link String}s transformations
	 */
	public ManifestEntrySignatureScope(final String entryName, final Digest digest, final String manifestName, 
			final List<String> transformations) {
		super(entryName, digest, transformations);
		this.manifestName = manifestName;
	}

	@Override
	public String getDescription() {
		String description;
		if (DomUtils.isElementReference(getName())) {
			description = String.format("The XML Manifest Entry with ID '%s' from a Manifest with name '%s'", getName(), manifestName);
		} else {
			description = String.format("The File Manifest Entry with name '%s' from a Manifest with name '%s'", getName(), manifestName);
		}
		if (isTransformationsNotEmpty()) {
			description = addTransformationDescription(description);
		}
		return description;
	}

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.FULL;
	}

}
