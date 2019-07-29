package eu.europa.esig.dss.validation.scope;

import java.util.List;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.enumerations.SignatureScopeType;

public final class ManifestSignatureScope extends SignatureScopeWithTransformations {

	public ManifestSignatureScope(final String name, final Digest digest) {
		super(name, digest, null);
	}

	public ManifestSignatureScope(final String name, final Digest digest, final List<String> transformations) {
		super(name, digest, transformations);
	}

    @Override
    public String getDescription() {
        return "Manifest document";
    }

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.FULL;
	}

}
