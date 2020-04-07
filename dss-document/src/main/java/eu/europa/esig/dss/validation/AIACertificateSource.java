package eu.europa.esig.dss.validation;

import java.security.PublicKey;
import java.util.Collection;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;

public class AIACertificateSource extends CommonCertificateSource {

	private static final long serialVersionUID = -2604947158902474169L;

	private static final Logger LOG = LoggerFactory.getLogger(AIACertificateSource.class);

	private final CertificateToken certificate;
	private final DataLoader dataLoader;

	public AIACertificateSource(CertificateToken certificate, DataLoader dataLoader) {
		Objects.requireNonNull(certificate, "The certificate cannot be null");
		Objects.requireNonNull(dataLoader, "The data loader cannot be null");
		this.certificate = certificate;
		this.dataLoader = dataLoader;
	}

	/**
	 * Get the issuer's certificate from Authority Information Access through
	 * id-ad-caIssuers extension.
	 *
	 * @return {@code CertificateToken} representing the issuer certificate or null.
	 */
	public CertificateToken getIssuerFromAIA() {
		LOG.info("Retrieving {} certificate's issuer using AIA.", certificate.getAbbreviation());
		Collection<CertificateToken> candidates = DSSUtils.loadPotentialIssuerCertificates(certificate, dataLoader);
		if (Utils.isCollectionNotEmpty(candidates)) {
			// The potential issuers might support 3 known scenarios:
			// - issuer certificate with single entry
			// - issuer certificate is a collection of bridge certificates (all having the
			// same public key)
			// - full certification path (up to the root of the chain)
			// In case the issuer is a collection of bridge certificates, only one of the
			// bridge certificates needs to be verified
			CertificateToken bridgedIssuer = findBestBridgeCertificate(candidates);
			if (bridgedIssuer != null) {
				addCertificate(bridgedIssuer);
				return bridgedIssuer;
			}
			for (CertificateToken candidate : candidates) {
				addCertificate(candidate);
			}
			for (CertificateToken candidate : candidates) {
				if (certificate.isSignedBy(candidate)) {
					if (!certificate.getIssuerX500Principal().equals(candidate.getSubject().getPrincipal())) {
						LOG.info("There is AIA extension, but the issuer subject name and subject name does not match.");
						LOG.info("CERT ISSUER    : {}", certificate.getIssuer().getCanonical());
						LOG.info("ISSUER SUBJECT : {}", candidate.getSubject().getCanonical());
					}
					return candidate;
				}
			}
			LOG.warn("The retrieved certificate(s) using AIA does not sign the certificate {}.", certificate.getAbbreviation());
		}
		return null;
	}

	private CertificateToken findBestBridgeCertificate(Collection<CertificateToken> candidates) {
		if (Utils.collectionSize(candidates) <= 1) {
			return null;
		}
		PublicKey commonPublicKey = null;
		CertificateToken bestMatch = null;
		for (CertificateToken candidate : candidates) {
			PublicKey candidatePublicKey = candidate.getPublicKey();
			if (commonPublicKey == null) {
				if (!certificate.isSignedBy(candidate)) {
					return null;
				}
				commonPublicKey = candidatePublicKey;
				bestMatch = candidate;
			} else if (!candidatePublicKey.equals(commonPublicKey)) {
				return null;
			} else if (isTrusted(bestMatch)) {
				continue;
			}

//			Set<CertificateToken> tokensSet = validationCertificatePool.get(candidate.getSubject());
//			for (CertificateToken pooledToken : tokensSet) {
//				if (pooledToken.getPublicKey().equals(commonPublicKey) && isTrusted(pooledToken)) {
//					bestMatch = pooledToken;
//					certificate.isSignedBy(pooledToken);
//					break;
//				}
//			}
		}

		return bestMatch;
	}

	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.AIA;
	}

}
