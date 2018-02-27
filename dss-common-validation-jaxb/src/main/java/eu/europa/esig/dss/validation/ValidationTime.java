package eu.europa.esig.dss.validation;

public enum ValidationTime {

	/**
	 * Not before date of the certificate
	 */
	CERTIFICATE_ISSUANCE_TIME,

	/**
	 * Lowest time at which there exists a POE for the signature
	 */
	BEST_SIGNATURE_TIME,

	/**
	 * Date of the validation
	 */
	VALIDATION_TIME

}
