package eu.europa.esig.dss.web.model;

import javax.validation.constraints.NotNull;

public class SignatureValueAsString {

	@NotNull
	private String signatureValue;

	public SignatureValueAsString() {
	}

	public SignatureValueAsString(String signatureValue) {
		this.signatureValue = signatureValue;
	}

	public String getSignatureValue() {
		return signatureValue;
	}

	public void setSignatureValue(String signatureValue) {
		this.signatureValue = signatureValue;
	}
}
