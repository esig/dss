package eu.europa.esig.dss.signature;

import java.util.LinkedList;
import java.util.List;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.CertificateReorderer;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class is used to retrieve the used certificates for a signature from the user parameters.
 * 
 * It avoids duplicate entries, orders certificates from the signing certificate to the Root CA and filters trust
 * anchors depending of the policy
 */
public class BaselineBCertificateSelector extends CertificateReorderer {

	private final CertificateVerifier certificateVerifier;
	private final AbstractSignatureParameters parameters;

	public BaselineBCertificateSelector(CertificateVerifier certificateVerifier, AbstractSignatureParameters parameters) {
		super(parameters.getSigningCertificate(), parameters.getCertificateChain());
		this.certificateVerifier = certificateVerifier;
		this.parameters = parameters;
	}

	public List<CertificateToken> getCertificates() {

		List<CertificateToken> orderedCertificates = getOrderedCertificates();

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

}
