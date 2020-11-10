package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

public class XAdESCounterSignatureParameters extends XAdESSignatureParameters implements SerializableCounterSignatureParameters {
	
	/**
	 * Signature Id to be counter signed
	 * 
	 * Can be a DSS Id or XMLDSIG Signature Id
	 */
	private String signatureIdToCounterSign;
	
	/**
	 * The canonicalization method used for a SignatureValue canonicalization
	 * The EXCLUSIVE canonicalization is used by default
	 */
	private String counterSignatureCanonicalizationMethod = DSSXMLUtils.DEFAULT_DSS_C14N_METHOD;

	@Override
	public String getSignatureIdToCounterSign() {
		return signatureIdToCounterSign;
	}
	
	@Override
	public void setSignatureIdToCounterSign(String signatureId) {
		this.signatureIdToCounterSign = signatureId;
	}

	/**
	 * Returns a canonicalization method used for a counter signed SignatureValue
	 * 
	 * @return {@link String} canonicalization method to use
	 */
	public String getCounterSignatureCanonicalizationMethod() {
		return counterSignatureCanonicalizationMethod;
	}

	/**
	 * Sets a canonicalization method used for a counter signed SignatureValue
	 * 
	 * @param counterSignatureCanonicalizationMethod {@link String} canonicalization method to use
	 */
	public void setCounterSignatureCanonicalizationMethod(String counterSignatureCanonicalizationMethod) {
		this.counterSignatureCanonicalizationMethod = counterSignatureCanonicalizationMethod;
	}

	@Override
	public String getDeterministicId() {
		if (deterministicId == null) {
			final TokenIdentifier identifier = (getSigningCertificate() == null ? null : getSigningCertificate().getDSSId());
			deterministicId = DSSUtils.getCounterSignatureDeterministicId(bLevel().getSigningDate(), identifier, signatureIdToCounterSign);
		}
		return deterministicId;
	}

}
