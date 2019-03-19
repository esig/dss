package eu.europa.esig.dss.validation;

public enum RevocationOriginType {

	/**
	 * The revocation data was embedded in the signature 'revocation-values' attribute (used in CAdES and XAdES)
	 */
	INTERNAL_REVOCATION_VALUES,

	/**
	 * The revocation data was embedded in the signature 'AttributeRevocationValues' attribute (used in XAdES)
	 */
	INTERNAL_ATTRIBUTE_REVOCATION_VALUES,

	/**
	 * The revocation data was embedded in the signature 'TimeStampValidationData' attribute (used in XAdES)
	 */
	INTERNAL_TIMESTAMP_REVOCATION_VALUES,

	/**
	 * The revocation data was embedded to the contents of DSS PDF dictionary (used in PAdES)
	 */
	INTERNAL_DSS,

	/**
	 * The revocation data was embedded to VRI dictionary (used in PAdES)
	 */
	INTERNAL_VRI,

	/**
	 * The revocation data was provided by the user or online OCSP/CRL
	 */
	EXTERNAL,
	
	/**
	 * The revocation data was obtained from a local DB or cache
	 */
	CACHED,

}
