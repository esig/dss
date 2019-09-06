package eu.europa.esig.dss.validation.process;

public enum ValidationProcessDefinition {

	VPBS("Validation Process for Basic Signatures"),

	VPFTSP("Validation Process for Timestamps"),

	VPFLTVD("Validation Process for Signatures with Time and Signatures with Long-Term Validation Data"),

	VPFSWATSP("Validation Process for Signatures with Archival Data"),

	SUB_XCV("Certificate Id"),

	TL("Trusted List"),

	SIG_QUALIFICATION("Signature Qualification"),

	CERT_QUALIFICATION("Certificate Qualification");

	private final String title;

	ValidationProcessDefinition(String title) {
		this.title = title;
	}

	public String getTitle() {
		return title;
	}

}
