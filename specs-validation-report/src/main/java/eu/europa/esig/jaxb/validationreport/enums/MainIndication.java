package eu.europa.esig.jaxb.validationreport.enums;

public enum MainIndication implements UriBasedEnum {

	// When present in the validation report of a signature, the following URIs
	// shall be used to represent the main status indication:
	TOTAL_PASSED("urn:etsi:019102:mainindication:total-passed"),

	TOTAL_FAILED("urn:etsi:019102:mainindication:total-failed"),

	INDETERMINATE("urn:etsi:019102:mainindication:indeterminate"),

	// When present in an individual validation constraint report element (see
	// clause 4.3.5.4) or a validation report of a signature validation object (see
	// clause 4.4.8), the following URIs shall be used to represent the main status
	// indication:
	PASSED("urn:etsi:019102:mainindication:passed"),

	FAILED("urn:etsi:019102:mainindication:failed");

	private final String uri;

	private MainIndication(String uri) {
		this.uri = uri;
	}

	public String getUri() {
		return uri;
	}

}
