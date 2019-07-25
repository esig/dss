package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.x509.SignaturePolicy;

public class ZeroHashSignaturePolicyValidator extends AbstractSignaturePolicyValidator {

	@Override
	public boolean canValidate() {
		SignaturePolicy policy = getSignaturePolicy();
		return policy.isZeroHash();
	}

	@Override
	public void validate() {
		setIdentified(true);
		setStatus(true);
	}

}
