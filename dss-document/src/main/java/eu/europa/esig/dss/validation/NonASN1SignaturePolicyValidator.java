package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.SignaturePolicy;

/**
 * This class covers the case of non ASN1 signature policies (eg : PDF file and its digest)
 */
public class NonASN1SignaturePolicyValidator extends AbstractSignaturePolicyValidator implements SignaturePolicyValidator {

	@Override
	public boolean canValidate() {
		SignaturePolicy policy = getSignaturePolicy();
		if (policy.getPolicyContent() != null) {
			byte firstByte = DSSUtils.readFirstByte(policy.getPolicyContent());
			return !DSSASN1Utils.isASN1SequenceTag(firstByte);
		}
		return false;
	}

	@Override
	public void validate() {
		setIdentified(true);

		SignaturePolicy signaturePolicy = getSignaturePolicy();
		String digestValue = signaturePolicy.getDigestValue();
		DigestAlgorithm signPolicyHashAlgFromSignature = signaturePolicy.getDigestAlgorithm();

		String recalculatedDigestValue = Utils.toBase64(DSSUtils.digest(signPolicyHashAlgFromSignature, signaturePolicy.getPolicyContent()));
		if (Utils.areStringsEqual(digestValue, recalculatedDigestValue)) {
			setStatus(true);
			setDigestAlgorithmsEqual(true);
		} else {
			addError("general",
					"The policy digest value (" + digestValue + ") does not match the re-calculated digest value (" + recalculatedDigestValue + ").");
		}
	}

}
