package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.enumerations.SignatureScopeType;

public class ContainerSignatureScope extends SignatureScope {
	
	private static final String DEFAULT_CONTAINER_NAME = "package.zip";

	public ContainerSignatureScope(Digest digest) {
		super(DEFAULT_CONTAINER_NAME, digest);
	}

	public ContainerSignatureScope(String name, Digest digest) {
		super(name, digest);
	}

    @Override
    public String getDescription() {
        return "ASiCS archive";
    }

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.FULL;
	}

}
