package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;

public class DigestSignatureScope extends SignatureScope {

	public DigestSignatureScope(String name, Digest digest) {
		super(name, digest);
	}

    @Override
    public String getDescription() {
        return "Digest of the document content";
    }

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.DIGEST;
	}

}
