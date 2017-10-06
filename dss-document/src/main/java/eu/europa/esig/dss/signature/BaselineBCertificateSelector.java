package eu.europa.esig.dss.signature;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class is used to retrieve the used certificates for a signature from the user parameters.
 * 
 * It avoids duplicate entries, orders certificates from the signing certificate to the Root CA and filters trust
 * anchors depending of the policy
 */
public class BaselineBCertificateSelector {

	private static final Logger LOG = LoggerFactory.getLogger(BaselineBCertificateSelector.class);

	private final CertificateVerifier certificateVerifier;
	private final AbstractSignatureParameters parameters;

	public BaselineBCertificateSelector(CertificateVerifier certificateVerifier, AbstractSignatureParameters parameters) {
		this.certificateVerifier = certificateVerifier;
		this.parameters = parameters;
	}

	public List<CertificateToken> getCertificates() {

		List<CertificateToken> orderedCertificates = order(getAllCertificatesOnce());

		CertificateSource trustedCertSource = certificateVerifier.getTrustedCertSource();

		// if true, trust anchor certificates (and upper certificates) are not included in the signature
		if (parameters.bLevel().isTrustAnchorBPPolicy() && trustedCertSource != null) {

			List<CertificateToken> result = new LinkedList<CertificateToken>();
			for (CertificateToken certificateToken : orderedCertificates) {
				if (!trustedCertSource.get(certificateToken.getSubjectX500Principal()).isEmpty()) {
					// trust anchor and its parents are skipped
					break;
				}
				result.add(certificateToken);
			}

			return result;
		} else {
			return orderedCertificates;
		}
	}

	/**
	 * This method is used to avoid duplicate entries
	 * 
	 * @return a list with all certificates
	 */
	private List<CertificateToken> getAllCertificatesOnce() {
		List<CertificateToken> result = new ArrayList<CertificateToken>();

		CertificateToken signingCertificate = parameters.getSigningCertificate();
		if (signingCertificate != null) {
			result.add(signingCertificate);
		}

		List<CertificateToken> certificateChain = parameters.getCertificateChain();
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
	 * This method is used to order the certificates (signing certificate -> CA1 -> CA2 -> Root)
	 * 
	 * @param certificates
	 * @return
	 */
	private List<CertificateToken> order(List<CertificateToken> certificates) {
		// Build the chain cert -> issuer
		for (CertificateToken token : certificates) {
			if (!token.isSelfSigned() && token.getIssuerToken() == null) {
				for (CertificateToken signer : certificates) {
					if (token.isSignedBy(signer)) {
						LOG.debug("{} is signed by {}", token.getDSSIdAsString(), signer.getDSSIdAsString());
						break;
					}
				}
				if (!token.isSelfSigned() && token.getIssuerToken() == null) {
					LOG.warn("Issuer not found for certificate {}", token.getDSSIdAsString());
				}
			}
		}

		// Build complete chain
		List<CertificateToken> result = new LinkedList<CertificateToken>();
		CertificateToken certToAdd = getSigningCertificate(certificates);
		while (certToAdd != null) {
			result.add(certToAdd);
			certToAdd = certToAdd.getIssuerToken();
		}

		if (certificates.size() != result.size()) {
			LOG.warn("Some certificates are ignored");
			LOG.warn("Before : {}", certificates);
			LOG.warn("After : {}", result);
		}

		return result;
	}

	/**
	 * This method is used to identify the signing certificate (the certificate which didn't sign any other certificate)
	 * 
	 * @param certificates
	 * @return
	 */
	private CertificateToken getSigningCertificate(List<CertificateToken> certificates) {
		List<CertificateToken> potentialSigners = new ArrayList<CertificateToken>();
		for (CertificateToken signer : certificates) {
			boolean isSigner = false;

			for (CertificateToken token : certificates) {
				if (signer.equals(token.getIssuerToken())) {
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
			CertificateToken signingCertificateParam = parameters.getSigningCertificate();
			if (signingCertificateParam != null && !signingCertificateParam.equals(signer)) {
				LOG.warn("Identified signer is different than parameter");
			}
			return signer;
		} else {
			LOG.warn("More than one identified signers");
			CertificateToken signingCertificateParam = parameters.getSigningCertificate();
			if (signingCertificateParam != null && potentialSigners.contains(signingCertificateParam)) {
				return signingCertificateParam;
			}
			return potentialSigners.get(0);
		}

	}

}
