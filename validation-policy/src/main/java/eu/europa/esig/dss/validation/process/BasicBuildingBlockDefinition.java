package eu.europa.esig.dss.validation.process;

import eu.europa.esig.dss.enumerations.UriBasedEnum;

public enum BasicBuildingBlockDefinition implements UriBasedEnum {

	FORMAT_CHECKING("Format Checking", "urn:cef:dss:bbb:formatChecking"),

	IDENTIFICATION_OF_THE_SIGNING_CERTIFICATE("Identification of the Signing Certificate", "urn:cef:dss:bbb:identificationOfTheSigningCertificate"),

	VALIDATION_CONTEXT_INITIALIZATION("Validation Context Initialization", "urn:cef:dss:bbb:validationContextInitialization"),

	CRYPTOGRAPHIC_VERIFICATION("Cryptographic Verification", "urn:cef:dss:bbb:cryptographicVerification"),

	SIGNATURE_ACCEPTANCE_VALIDATION("Signature Acceptance Validation", "urn:cef:dss:bbb:signatureAcceptanceValidation"),

	X509_CERTIFICATE_VALIDATION("X509 Certificate Validation", "urn:cef:dss:bbb:x509CertificateValidation"),

	REVOCATION_FRESHNESS_CHECKER("Revocation Freshness Checker", "urn:cef:dss:bbb:revocationFreshnessChecker"),

	PAST_SIGNATURE_VALIDATION("Past Signature Validation", "urn:cef:dss:bbb:pastSignatureValidation"),

	PAST_CERTIFICATE_VALIDATION("Past Certificate Validation", "urn:cef:dss:bbb:pastCertificateValidation"),

	VALIDATION_TIME_SLIDING("Validation Time Sliding", "urn:cef:dss:bbb:validationTimeSliding");

	private final String title;
	private final String uri;

	BasicBuildingBlockDefinition(String title, String uri) {
		this.title = title;
		this.uri = uri;
	}

	public String getTitle() {
		return title;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
