package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;

public class JAdESCounterSignatureParameters extends JAdESSignatureParameters implements SerializableCounterSignatureParameters {
	
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
