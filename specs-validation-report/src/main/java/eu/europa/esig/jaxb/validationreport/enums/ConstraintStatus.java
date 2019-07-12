package eu.europa.esig.jaxb.validationreport.enums;

import eu.europa.esig.dss.enumerations.UriBasedEnum;

public enum ConstraintStatus implements UriBasedEnum {
	
	APPLIED("urn:etsi:019102:constraintStatus:applied"),
	
	DISABLED("urn:etsi:019102:constraintStatus:disabled"),
	
	OVERRIDDEN("urn:etsi:019102:constraintStatus:overridden");
	
	private final String uri;

	ConstraintStatus(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
