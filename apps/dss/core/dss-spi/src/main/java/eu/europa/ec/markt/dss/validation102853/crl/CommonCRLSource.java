package eu.europa.ec.markt.dss.validation102853.crl;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import sun.security.x509.DistributionPointName;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.IssuingDistributionPointExtension;
import sun.security.x509.PKIXExtensions;
import sun.security.x509.URIName;

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
	 * issuer name of the certificate for which the verification of the revocation data is carried out. A dedicated object based on {@code CRLValidity} is created and accordingly
	 * updated.
	 *
	 * @param x509CRL     {@code X509CRL} to be verified (cannot be null)
	 * @param issuerToken {@code CertificateToken} used to sign the {@code X509CRL} (cannot be null)
	 * @return {@code CRLValidity}
	 */
	protected CRLValidity isValidCRL(final X509CRL x509CRL, final CertificateToken issuerToken) {

		final CRLValidity crlValidity = new CRLValidity();
		crlValidity.x509CRL = x509CRL;

		final X500Principal x509CRLIssuerX500Principal = DSSUtils.getX500Principal(x509CRL.getIssuerX500Principal());
		final X500Principal issuerTokenSubjectX500Principal = DSSUtils.getX500Principal(issuerToken.getSubjectX500Principal());
		if (x509CRLIssuerX500Principal.equals(issuerTokenSubjectX500Principal)) {

			crlValidity.issuerX509PrincipalMatches = true;
		}
		checkCriticalExtensions(x509CRL, crlValidity);
		checkSignatureValue(x509CRL, issuerToken, crlValidity);
		if (crlValidity.signatureIntact) {

			crlValidity.crlSignKeyUsage = issuerToken.hasCRLSignKeyUsage();
		}
		return crlValidity;
	}

	private void checkSignatureValue(final X509CRL x509CRL, final CertificateToken issuerToken, final CRLValidity crlValidity) {

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
	}

	private void checkCriticalExtensions(final X509CRL x509CRL, final CRLValidity crlValidity) {

		try {

			final Set<String> criticalExtensionOIDs = x509CRL.getCriticalExtensionOIDs();
			if (criticalExtensionOIDs == null || criticalExtensionOIDs.size() == 0) {
				crlValidity.unknownCriticalExtension = false;
			} else {

				for (final String criticalExtensionOID : criticalExtensionOIDs) {

					final String oid = PKIXExtensions.IssuingDistributionPoint_Id.toString();
					if (criticalExtensionOID.equals(oid)) {

						final byte[] extensionValue_ = x509CRL.getExtensionValue(oid);
						int firstIndex = 0;
						for (; firstIndex < extensionValue_.length; firstIndex++) {

							if (extensionValue_[firstIndex] == 0x30) {
								break;
							}
						}
						final byte[] extensionValue = Arrays.copyOfRange(extensionValue_, firstIndex, extensionValue_.length);
						final IssuingDistributionPointExtension issuingDistributionPointExtension = new IssuingDistributionPointExtension(true, extensionValue);
						final Boolean onlyAttributeCerts = (Boolean) issuingDistributionPointExtension.get(IssuingDistributionPointExtension.ONLY_ATTRIBUTE_CERTS);
						final Boolean onlyCaCerts = (Boolean) issuingDistributionPointExtension.get(IssuingDistributionPointExtension.ONLY_CA_CERTS);
						final Boolean onlyUserCerts = (Boolean) issuingDistributionPointExtension.get(IssuingDistributionPointExtension.ONLY_USER_CERTS);
						final Boolean indirectCrl = (Boolean) issuingDistributionPointExtension.get(IssuingDistributionPointExtension.INDIRECT_CRL);
						final String reasons = (String) issuingDistributionPointExtension.get(IssuingDistributionPointExtension.REASONS);
						final DistributionPointName distributionPointName = (DistributionPointName) issuingDistributionPointExtension.get(IssuingDistributionPointExtension.POINT);
						final GeneralNames fullName = distributionPointName.getFullName();
						final List<GeneralName> names = fullName.names();
						boolean urlFound = false;
						if (names.size() > 0) {
							final URIName name = (URIName) names.get(0).getName();
							//LOG.trace("--> CRL IssuingDistributionPoint Extension: URI: " + name.getURI());
							// TODO (25/11/2014): The check with the CDP must be done.
							urlFound = true;
						}
						if (!(onlyAttributeCerts && onlyCaCerts && onlyUserCerts && indirectCrl) && reasons == null && urlFound) {
							crlValidity.unknownCriticalExtension = false;
						}
					} else {
						break;
					}
				}
			}
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}
}