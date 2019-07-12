package eu.europa.esig.jaxb.validationreport.enums;

import eu.europa.esig.dss.enumerations.UriBasedEnum;

public enum SignatureValidationProcessID implements UriBasedEnum {

	/**
	 * when the SVA performed the Validation Process for Basic Signatures as
	 * specified in ETSI TS 119 102-1 [1], clause 5.3.
	 */
	BASIC("urn::etsi:019102:validationprocess:Basic"),

	/**
	 * when the SVA performed the Validation Process for Signatures with Time and
	 * Signatures with LongTerm-Validation Material as specified in ETSI TS 119
	 * 102-1 [1], clause 5.5.
	 */
	LTVM("urn::etsi:019102:validationprocess:LTVM"),

	/**
	 * when the SVA performed the Validation process for Signatures providing Long
	 * Term Availability and Integrity of Validation Material as specified in ETSI
	 * TS 119 102-1 [1], clause 5.6.
	 */
	LTA("urn::etsi:019102:validationprocess:LTA");

	private final String uri;

	SignatureValidationProcessID(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
