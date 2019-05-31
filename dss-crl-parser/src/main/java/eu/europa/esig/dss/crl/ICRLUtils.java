package eu.europa.esig.dss.crl;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.X509CRLEntry;

import eu.europa.esig.dss.x509.CertificateToken;

public interface ICRLUtils {

	/**
	 * This method verifies: the signature of the CRL, the key usage of its signing certificate and the coherence
	 * between the subject names of the CRL signing certificate and the issuer name of the certificate for which the
	 * verification of the revocation data is carried out. A dedicated object based on {@code CRLValidity} is created
	 * and accordingly updated.
	 *
	 * @param crlStream
	 *            {@code InputStream} with the CRL to be verified (cannot be null)
	 * @param issuerToken
	 *            {@code CertificateToken} used to sign the {@code X509CRL} (cannot be null)
	 * @return {@code CRLValidity}
	 * @throws IOException
	 */
	CRLValidity isValidCRL(final InputStream crlStream, final CertificateToken issuerToken) throws IOException;

	/**
	 * This method verifies the revocation status for a given serial number
	 * 
	 * @param crlValidity
	 *            the CRL Validity
	 * @param serialNumber
	 *            the certificate serial number to search
	 * @return the X509CRLEntry with the revocation date, the reason, or null if the serial number is not found
	 */
	X509CRLEntry getRevocationInfo(final CRLValidity crlValidity, final BigInteger serialNumber);

}
