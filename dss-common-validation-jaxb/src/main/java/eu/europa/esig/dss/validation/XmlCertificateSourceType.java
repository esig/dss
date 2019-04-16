package eu.europa.esig.dss.validation;

/**
 * Standard sources for a certificate. Indicates where the certificate comes from.
 */
public enum XmlCertificateSourceType {

	TRUSTED_STORE, TRUSTED_LIST, SIGNATURE, OCSP_RESPONSE, OTHER, AIA, TIMESTAMP, UNKNOWN;

}
