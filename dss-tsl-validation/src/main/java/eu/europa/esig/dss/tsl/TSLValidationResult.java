package eu.europa.esig.dss.tsl;

import eu.europa.esig.dss.validation.policy.rules.Indication;

public class TSLValidationResult {

	private String countryCode;
	private String indication;
	private String subIndication;

	public String getCountryCode() {
		return countryCode;
	}

	public void setCountryCode(String countryCode) {
		this.countryCode = countryCode;
	}

	public String getIndication() {
		return indication;
	}

	public void setIndication(String indication) {
		this.indication = indication;
	}

	public String getSubIndication() {
		return subIndication;
	}

	public void setSubIndication(String subIndication) {
		this.subIndication = subIndication;
	}

	public boolean isValid() {
		return Indication.VALID.equals(indication);
	}

	public boolean isIndeterminate() {
		return Indication.INDETERMINATE.equals(indication);
	}

	public boolean isInvalid() {
		return Indication.INVALID.equals(indication);
	}

}
