package eu.europa.esig.dss.tsl;

public class TSLValidationResult {

	private String countryCode;
	private boolean signatureValid;

	public String getCountryCode() {
		return countryCode;
	}

	public void setCountryCode(String countryCode) {
		this.countryCode = countryCode;
	}

	public boolean isSignatureValid() {
		return signatureValid;
	}

	public void setSignatureValid(boolean signatureValid) {
		this.signatureValid = signatureValid;
	}

}
