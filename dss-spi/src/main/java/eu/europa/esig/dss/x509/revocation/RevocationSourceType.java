package eu.europa.esig.dss.x509.revocation;

import eu.europa.esig.dss.x509.RevocationToken;

/**
 * Defines a type of revocation data response
 */
public enum RevocationSourceType {

	/**
	 * The {@link RevocationToken} was received from CRL response
	 */
	CRL,

	/**
	 * The {@link RevocationToken} was received from OCSP response
	 */
	OCSP,

}
