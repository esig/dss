package eu.europa.ec.markt.dss.validation102853.crl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * This is the representation of simple (common) CRL source, this is the base class for all real implementations.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public abstract class CommonCRLSource implements CRLSource {

	/**
	 * This method verifies: the signature of the CRL, the key usage of its signing certificate and the coherence between the subject names of the CRL signing certificate and the
	 * issuer name of the certificate for which the verification of the revocation data is carried out. If one of the tests fails {@code null} is returned. If CRL or signing
	 * certificate are {@code null} than {@code null} is returned.
	 *
	 * @param x509CRL     CRL to be verified (can be null)
	 * @param issuerToken CRL signing certificate (can be null)
	 * @return CRL list or null
	 */
	protected CRLValidity isValidCRL(final X509CRL x509CRL, final CertificateToken issuerToken) {

		final CRLValidity crlValidity = new CRLValidity();
		crlValidity.x509CRL = x509CRL;

		final X500Principal x509CRLIssuerX500Principal = DSSUtils.getX500Principal(x509CRL.getIssuerX500Principal());
		final X500Principal issuerTokenSubjectX500Principal = DSSUtils.getX500Principal(issuerToken.getSubjectX500Principal());
		if (x509CRLIssuerX500Principal.equals(issuerTokenSubjectX500Principal)) {

			crlValidity.issuerX509PrincipalMatches = true;
		}
		try {

			x509CRL.verify(issuerToken.getPublicKey());
			crlValidity.signatureIntact = true;
			crlValidity.issuerToken = issuerToken;
		} catch (InvalidKeyException e) {
			crlValidity.signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
		} catch (CRLException e) {
			crlValidity.signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
		} catch (NoSuchAlgorithmException e) {
			crlValidity.signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
		} catch (SignatureException e) {
			crlValidity.signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
		} catch (NoSuchProviderException e) {
			throw new DSSException(e);
		}
		if (crlValidity.signatureIntact) {

			crlValidity.hasCRLSignKeyUsage = issuerToken.hasCRLSignKeyUsage();
		}
		return crlValidity;
	}
}