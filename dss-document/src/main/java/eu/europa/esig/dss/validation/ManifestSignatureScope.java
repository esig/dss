package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.enumerations.SignatureScopeType;

public final class ManifestSignatureScope extends SignatureScope {

	public ManifestSignatureScope(String name, Digest digest) {
		super(name, digest);
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
