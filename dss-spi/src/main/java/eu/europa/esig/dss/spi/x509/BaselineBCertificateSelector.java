/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * This class is used to retrieve the used certificates for a signature from the user parameters.
 * It avoids duplicate entries, orders certificates from the signing certificate to the Root CA and filters trust
 * anchors depending on the policy.
 *
 */
public class BaselineBCertificateSelector extends CertificateReorderer {

	/**
	 * The trusted certificate source to be used on certificate chain building.
	 */
	private CertificateSource trustedCertificateSource;

	/**
	 * Indicates whether a trust anchor policy should be used.
	 * When enabled, the trust anchor is not included to the generated certificate chain.
	 * Otherwise, the chain is generated up to a trust anchor, including the trust anchor itself.
	 */
	private boolean trustAnchorBPPolicy = true;

	/**
	 * Constructor to build a certificate chain for {@code signingCertificate}
	 *
	 * @param signingCertificate {@link CertificateToken} identifies a signing-certificate to build a certificate chain for
	 * @param certificateChain a collection of {@link CertificateToken} to build a certificate chain from
	 */
	public BaselineBCertificateSelector(CertificateToken signingCertificate, Collection<CertificateToken> certificateChain) {
		super(signingCertificate, certificateChain);
	}

	/**
	 * Sets the trusted certificate source
	 *
	 * @param trustedCertificateSource {@link CertificateSource}
	 * @return this {@link BaselineBCertificateSelector}
	 */
	public BaselineBCertificateSelector setTrustedCertificateSource(CertificateSource trustedCertificateSource) {
		this.trustedCertificateSource = trustedCertificateSource;
		return this;
	}

	/**
	 * Sets whether a trust anchor policy should be used.
	 * When enabled, the trust anchor is not included to the generated certificate chain.
	 * Otherwise, the chain is generated up to a trust anchor, including the trust anchor itself.
	 * Default : TRUE (trust anchor is not included to the generated certificate chain)
	 *
	 * @param trustAnchorBPPolicy whether a trust anchor policy should be used
	 * @return this {@link BaselineBCertificateSelector}
	 */
	public BaselineBCertificateSelector setTrustAnchorBPPolicy(boolean trustAnchorBPPolicy) {
		this.trustAnchorBPPolicy = trustAnchorBPPolicy;
		return this;
	}

	/**
	 * Returns a certificate chain for a B-level signature creation
	 *
	 * @return an ordered list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getCertificates() {
		List<CertificateToken> orderedCertificates = getOrderedCertificates();

		// if true, trust anchor certificates (and upper certificates) are not included in the signature
		if (trustAnchorBPPolicy && trustedCertificateSource != null) {
			List<CertificateToken> result = new LinkedList<>();
			for (CertificateToken certificateToken : orderedCertificates) {
				if (trustedCertificateSource.isTrusted(certificateToken)) {
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
