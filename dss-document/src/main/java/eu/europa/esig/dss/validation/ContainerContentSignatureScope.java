package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.enumerations.SignatureScopeType;

public class ContainerContentSignatureScope extends ContainerSignatureScope {

	public ContainerContentSignatureScope(String name, Digest digest) {
		super(name, digest);
	}

    @Override
    public String getDescription() {
        return "ASiCS archive content";
    }

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.ARCHIVED;
	}

}
