package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.x509.SignaturePolicy;

/**
 * This class covers the case of empty signature policies (no asn1,... file has been downloaded)
 */
public class EmptySignaturePolicyValidator extends AbstractSignaturePolicyValidator {

	@Override
	public boolean canValidate() {
		SignaturePolicy signaturePolicy = getSignaturePolicy();
		return signaturePolicy.getPolicyContent() == null;
	}

	@Override
	public void validate() {
		setStatus(getSignaturePolicy().getIdentifier().isEmpty());
	}

}
