package eu.europa.esig.dss.x509;

import java.io.Serializable;

/**
 * This interface allows to retrieve revocation data for a given certificate.
 * Several implementations are available based on CRL and OCSP.
 */
public interface RevocationSource<T extends RevocationToken> extends Serializable {

	/**
	 * This method retrieves a {@code RevocationToken} for the certificateToken
	 * 
	 * @param certificateToken
	 *                               The {@code CertificateToken} for which the
	 *                               request is made
	 * @param issuerCertificateToken
	 *                               The {@code CertificateToken} which is the
	 *                               issuer of the certificateToken
	 * @return an instance of {@code RevocationToken}
	 */
	T getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken);

}
