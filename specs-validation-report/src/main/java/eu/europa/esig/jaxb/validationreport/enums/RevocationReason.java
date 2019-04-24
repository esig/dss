package eu.europa.esig.jaxb.validationreport.enums;

public enum RevocationReason implements UriBasedEnum {
	
	unspecified("urn:etsi:019102:revocationReason:unspecified"),

	keyCompromise("urn:etsi:019102:revocationReason:keyCompromise"),

	cACompromise("urn:etsi:019102:revocationReason:cACompromise"),

	affiliationChanged("urn:etsi:019102:revocationReason:affiliationChanged"),

	superseded("urn:etsi:019102:revocationReason:superseded"),

	cessationOfOperation("urn:etsi:019102:revocationReason:cessationOfOperation"),

	certificateHold("urn:etsi:019102:revocationReason:certificateHold"),
	
	// Missing in standard
	removeFromCRL("urn:etsi:019102:revocationReason:removeFromCRL"),

	privilegeWithdrawn("urn:etsi:019102:revocationReason:privilegeWithdrawn"),
	
	// Missing in standard
	aACompromise("urn:etsi:019102:revocationReason:aACompromise");

	private final String uri;

	private RevocationReason(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
