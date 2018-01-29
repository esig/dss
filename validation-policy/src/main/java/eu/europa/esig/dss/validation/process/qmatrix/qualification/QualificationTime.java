package eu.europa.esig.dss.validation.process.qmatrix.qualification;

public enum QualificationTime {

	/**
	 * Not before date of the certificate
	 */
	CERTIFICATE_ISSUANCE_TIME,

	/**
	 * Date of the signature
	 */
	SIGNING_TIME,

	/**
	 * Date of the validation
	 */
	VALIDATION_TIME

}
