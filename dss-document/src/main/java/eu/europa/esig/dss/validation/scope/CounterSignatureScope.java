package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.Digest;

public class CounterSignatureScope extends SignatureScope {

    public CounterSignatureScope(final String masterSignatureId, Digest digest) {
        super(masterSignatureId, digest);
    }

    @Override
    public String getDescription() {
        return String.format("Master signature with Id : %s", getName());
    }

	@Override
	public SignatureScopeType getType() {
		return SignatureScopeType.COUNTER_SIGNATURE;
	}

}
