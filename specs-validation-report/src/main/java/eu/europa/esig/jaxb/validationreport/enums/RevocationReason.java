package eu.europa.esig.jaxb.validationreport.enums;

public enum RevocationReason implements UriBasedEnum {

	UNSPECIFIED("urn:etsi:019102:revocationReason:unspecified"),

	KEY_COMPROMISE("urn:etsi:019102:revocationReason:keyCompromise"),

	CA_COMPRIMISE("urn:etsi:019102:revocationReason:cACompromise"),

	AFFILIATION_CHANGED("urn:etsi:019102:revocationReason:affiliationChanged"),

	SUPERSEDED("urn:etsi:019102:revocationReason:superseded"),

	CESSATION_OF_OPERATION("urn:etsi:019102:revocationReason:cessationOfOperation"),

	CERTIFICATE_HOLD("urn:etsi:019102:revocationReason:certificateHold"),

	PRIVILEGE_WITHDRAWN("urn:etsi:019102:revocationReason:privilegeWithdrawn");

	private final String uri;

	private RevocationReason(String uri) {
		this.uri = uri;
	}

	public String getUri() {
		return uri;
	}

}
