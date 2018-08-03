package eu.europa.esig.dss;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

public class CertificateReorderer {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateReorderer.class);

	private final CertificateToken signingCertificate;
	private final List<CertificateToken> certificateChain;

	/**
	 * Constructor which takes a list of certificates where DSS needs to find the signing certificate
	 * 
	 * @param certificateChain
	 *            a list of certificates
	 */
	public CertificateReorderer(List<CertificateToken> certificateChain) {
		this(null, certificateChain);
	}

	/**
	 * Constructor which takes a potential signing certificate and a certificate chain
	 * 
	 * @param signingCertificate
	 *            the potential signing certificate
	 * @param certificateChain
	 *            the certificate chain
	 */
	public CertificateReorderer(CertificateToken signingCertificate, List<CertificateToken> certificateChain) {
		this.signingCertificate = signingCertificate;
		this.certificateChain = certificateChain;
	}

	/**
	 * This method is used to order the certificates (signing certificate, CA1, CA2 and Root)
	 * 
	 * @return a list of ordered certificates
	 */
	public List<CertificateToken> getOrderedCertificates() {

		List<CertificateToken> certificates = getAllCertificatesOnce();
		if (Utils.collectionSize(certificates) == 1) {
			return certificates;
		}

		// Build the chain cert -> issuer
		for (CertificateToken token : certificates) {
			if (isIssuerNeeded(token)) {
				for (CertificateToken signer : certificates) {
					if (token.isSignedBy(signer)) {
						LOG.debug("{} is signed by {}", token.getDSSIdAsString(), signer.getDSSIdAsString());
						break;
					}
				}
				if (isIssuerNeeded(token)) {
					LOG.warn("Issuer not found for certificate {}", token.getDSSIdAsString());
				}
			}
		}

		// Build complete chain
		List<CertificateToken> result = new LinkedList<CertificateToken>();
		CertificateToken certToAdd = getSigningCertificate(certificates);
		
		while (certToAdd != null && !result.contains(certToAdd)) {
			result.add(certToAdd);
			certToAdd = getCertificateByPubKey(certificates, certToAdd.getPublicKeyOfTheSigner());
		}

		if (certificates.size() > result.size()) {
			LOG.debug("Some certificates are ignored");
			LOG.debug("Before : {}", certificates);
			LOG.debug("After : {}", result);
		}

		return result;
	}

	private CertificateToken getCertificateByPubKey(List<CertificateToken> certificates, PublicKey publicKeyOfTheSigner) {
		for (CertificateToken certificateToken : certificates) {
			if (certificateToken.getPublicKey().equals(publicKeyOfTheSigner)) {
				return certificateToken;
			}
		}
		return null;
	}

	private boolean isIssuerNeeded(CertificateToken token) {
		return !token.isSelfSigned() && !token.isTrusted() && token.getPublicKeyOfTheSigner() == null;
	}

	/**
	 * This method is used to avoid duplicate entries
	 * 
	 * @return a list with all certificates
	 */
	private List<CertificateToken> getAllCertificatesOnce() {
		List<CertificateToken> result = new ArrayList<CertificateToken>();

		if (signingCertificate != null) {
			result.add(signingCertificate);
		}

		if (Utils.isCollectionNotEmpty(certificateChain)) {
			for (CertificateToken certificateToken : certificateChain) {
				if (certificateToken != null && !result.contains(certificateToken)) {
					result.add(certificateToken);
				}
			}
		}

		return result;
	}

	/**
	 * This method is used to identify the signing certificate (the certificate which didn't sign any other certificate)
	 * 
	 * @param certificates
	 * @return the identified signing certificate
	 */
	private CertificateToken getSigningCertificate(List<CertificateToken> certificates) {
		List<CertificateToken> potentialSigners = new ArrayList<CertificateToken>();
		for (CertificateToken signer : certificates) {
			boolean isSigner = false;

			for (CertificateToken token : certificates) {
				if (signer.getPublicKey().equals(token.getPublicKeyOfTheSigner())) {
					isSigner = true;
					break;
				}
			}

			if (!isSigner) {
				potentialSigners.add(signer);
			}
		}

		if (Utils.isCollectionEmpty(potentialSigners)) {
			throw new DSSException("No signing certificate found");
		} else if (Utils.collectionSize(potentialSigners) == 1) {
			CertificateToken signer = potentialSigners.get(0);
			if (signingCertificate != null && !signingCertificate.equals(signer)) {
				LOG.warn("Identified signer is different than parameter");
			}
			return signer;
		} else {
			if (signingCertificate != null && potentialSigners.contains(signingCertificate)) {
				return signingCertificate;
			}
			LOG.warn("More than one identified signers (returns first)");
			return potentialSigners.get(0);
		}
	}

}
