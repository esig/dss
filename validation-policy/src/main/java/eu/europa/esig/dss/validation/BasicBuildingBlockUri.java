package eu.europa.esig.dss.validation;

import eu.europa.esig.jaxb.validationreport.enums.UriBasedEnum;

public enum BasicBuildingBlockUri implements UriBasedEnum {

	FORMAT_CHECKING("urn:cef:dss:bbb:formatChecking"),

	IDENTIFICATION_OF_THE_SIGNING_CERTIFICATE("urn:cef:dss:bbb:identificationOfTheSigningCertificate"),

	VALIDATION_CONTEXT_INITIALIZATION("urn:cef:dss:bbb:validationContextInitialization"),

	CRYPTOGRAPHIC_VERIFICATION("urn:cef:dss:bbb:cryptographicVerification"),

	SIGNATURE_ACCEPTANCE_VALIDATION("urn:cef:dss:bbb:signatureAcceptanceValidation"),

	X509_CERTIFICATE_VALIDATION("urn:cef:dss:bbb:x509CertificateValidation"),

	PAST_SIGNATURE_VALIDATION("urn:cef:dss:bbb:pastSignatureValidation"),

	PAST_CERTIFICATE_VALIDATION("urn:cef:dss:bbb:pastCertificateValidation"),

	VALIDATION_TIME_SLIDING("urn:cef:dss:bbb:validationTimeSliding");

	private final String uri;

	BasicBuildingBlockUri(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
