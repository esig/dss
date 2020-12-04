package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;

/**
 * Parameters for a CAdES counter signature creation
 */
public class CAdESCounterSignatureParameters extends CAdESSignatureParameters implements SerializableCounterSignatureParameters {

	private static final long serialVersionUID = -1964623380368542439L;

	/**
	 * Signature Id to be counter signed
	 */
	private String signatureIdToCounterSign;

	@Override
	public String getSignatureIdToCounterSign() {
		return signatureIdToCounterSign;
	}

	@Override
	public void setSignatureIdToCounterSign(String signatureId) {
		this.signatureIdToCounterSign = signatureId;
	}

}
