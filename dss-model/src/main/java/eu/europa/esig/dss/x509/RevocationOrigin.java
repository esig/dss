package eu.europa.esig.dss.x509;

public enum RevocationOrigin {

	/**
	 * The revocation data was embedded in the signature
	 */
	SIGNATURE,

	/**
	 * The revocation data was provided by the user or online OCSP/CRL
	 */
	EXTERNAL

}
