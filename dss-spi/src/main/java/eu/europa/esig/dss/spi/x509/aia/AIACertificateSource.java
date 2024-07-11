/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509.aia;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.TokenIssuerSelector;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.util.Collection;
import java.util.Objects;

/**
 * The certificate source requesting issuer certificates by AIA
 */
public class AIACertificateSource extends CommonCertificateSource {

	private static final long serialVersionUID = -2604947158902474169L;

	private static final Logger LOG = LoggerFactory.getLogger(AIACertificateSource.class);

	/** The certificate token to get issuer for */
	private final CertificateToken certificate;

	/** Used to access the issuer certificates by AIA */
	private final AIASource aiaSource;

	/**
	 * Default constructor
	 *
	 * @param certificate {@link CertificateToken} to get the issuer for
	 * @param aiaSource {@link AIASource} to obtain the issuer certificate
	 */
	public AIACertificateSource(final CertificateToken certificate, final AIASource aiaSource) {
		Objects.requireNonNull(certificate, "The certificate cannot be null");
		Objects.requireNonNull(aiaSource, "The aiaSource cannot be null");
		this.certificate = certificate;
		this.aiaSource = aiaSource;
	}

	/**
	 * Get the issuer's certificate from Authority Information Access through
	 * id-ad-caIssuers extension.
	 *
	 * @return {@code CertificateToken} representing the issuer certificate or null.
	 */
	public CertificateToken getIssuerFromAIA() {
		LOG.info("Retrieving {} certificate's issuer using AIA.", certificate.getAbbreviation());

		try {
			Collection<CertificateToken> candidates = aiaSource.getCertificatesByAIA(certificate);
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

				CertificateToken issuer = new TokenIssuerSelector(certificate, candidates).getIssuer();
				if (issuer == null) {
					LOG.warn("The retrieved certificate(s) using AIA do not sign the certificate with Id : {}.",
							certificate.getDSSIdAsString());
				}
				return issuer;
			}

		} catch (Exception e) {
			LOG.warn("An error occurred on attempt to retrieve certificate's CA issuers : {}", e.getMessage(), e);
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
				if (bestMatch == null) {
					bestMatch = candidate;
				}

			} else if (!candidatePublicKey.equals(commonPublicKey)) {
				return null;

			}
			if (certificate.getIssuerX500Principal().equals(candidate.getSubject().getPrincipal())) {
				bestMatch = candidate;
			}
			if (candidate.isValidOn(certificate.getCreationDate())) {
				bestMatch = candidate;
				break;
			}
		}

		return bestMatch;
	}

	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.AIA;
	}

}
