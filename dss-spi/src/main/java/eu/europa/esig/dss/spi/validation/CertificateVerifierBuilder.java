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
package eu.europa.esig.dss.spi.validation;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;

/**
 * Builds a copy of CertificateVerifier
 */
public class CertificateVerifierBuilder {

	/** The CertificateVerifier to copy */
	private final CertificateVerifier certificateVerifier;

	/**
	 * Default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier} to copy
	 */
	public CertificateVerifierBuilder(CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	/**
	 * Builds a complete copy of the {@code certificateVerifier}
	 *
	 * @return {@link CertificateVerifier} copy
	 */
	public CertificateVerifier buildCompleteCopy() {
		CertificateVerifier copy = new CommonCertificateVerifier(true);
		if (certificateVerifier != null) {
			copy.setAIASource(certificateVerifier.getAIASource());
			copy.setCrlSource(certificateVerifier.getCrlSource());
			copy.setOcspSource(certificateVerifier.getOcspSource());
			copy.setRevocationDataLoadingStrategyFactory(certificateVerifier.getRevocationDataLoadingStrategyFactory());
			copy.setRevocationFallback(certificateVerifier.isRevocationFallback());
			copy.setRevocationDataVerifier(certificateVerifier.getRevocationDataVerifier());
			copy.setTimestampTokenVerifier(certificateVerifier.getTimestampTokenVerifier());
			copy.setTrustAnchorVerifier(certificateVerifier.getTrustAnchorVerifier());
			copy.setCheckRevocationForUntrustedChains(certificateVerifier.isCheckRevocationForUntrustedChains());
			copy.setAdjunctCertSources(certificateVerifier.getAdjunctCertSources());
			copy.setTrustedCertSources(certificateVerifier.getTrustedCertSources());

			copy.setAlertOnInvalidSignature(certificateVerifier.getAlertOnInvalidSignature());
			copy.setAlertOnInvalidTimestamp(certificateVerifier.getAlertOnInvalidTimestamp());
			copy.setAlertOnMissingRevocationData(certificateVerifier.getAlertOnMissingRevocationData());
			copy.setAlertOnNoRevocationAfterBestSignatureTime(certificateVerifier.getAlertOnNoRevocationAfterBestSignatureTime());
			copy.setAlertOnRevokedCertificate(certificateVerifier.getAlertOnRevokedCertificate());
			copy.setAlertOnUncoveredPOE(certificateVerifier.getAlertOnUncoveredPOE());
			copy.setAlertOnExpiredCertificate(certificateVerifier.getAlertOnExpiredCertificate());
			copy.setAlertOnNotYetValidCertificate(certificateVerifier.getAlertOnNotYetValidCertificate());
			copy.setAugmentationAlertOnSignatureWithoutCertificates(certificateVerifier.getAugmentationAlertOnSignatureWithoutCertificates());
			copy.setAugmentationAlertOnHigherSignatureLevel(certificateVerifier.getAugmentationAlertOnHigherSignatureLevel());
			copy.setAugmentationAlertOnSelfSignedCertificateChains(certificateVerifier.getAugmentationAlertOnSelfSignedCertificateChains());
		}
		return copy;
	}

	/**
	 * Builds a copy of the {@code certificateVerifier} by skipping the data sources and disabling alerts
	 *
	 * @return {@link CertificateVerifier} copy
	 */
	public CertificateVerifier buildOfflineAndSilentCopy() {
		CertificateVerifier offlineCertificateVerifier = new CommonCertificateVerifier(true);
		if (certificateVerifier != null) {
			offlineCertificateVerifier.setAdjunctCertSources(certificateVerifier.getAdjunctCertSources());
			offlineCertificateVerifier.setTrustedCertSources(certificateVerifier.getTrustedCertSources());
			offlineCertificateVerifier.setRevocationDataVerifier(certificateVerifier.getRevocationDataVerifier());
			offlineCertificateVerifier.setTimestampTokenVerifier(certificateVerifier.getTimestampTokenVerifier());
			offlineCertificateVerifier.setTrustAnchorVerifier(getTrustAnchorVerifierOfflineCopy(certificateVerifier.getTrustAnchorVerifier()));
		}
		// disable alerting
		offlineCertificateVerifier.setAlertOnInvalidSignature(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnInvalidTimestamp(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnRevokedCertificate(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnUncoveredPOE(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnNotYetValidCertificate(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAugmentationAlertOnSignatureWithoutCertificates(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());
		return offlineCertificateVerifier;
	}

	private TrustAnchorVerifier getTrustAnchorVerifierOfflineCopy(TrustAnchorVerifier originalTrustAnchorVerifier) {
		TrustAnchorVerifier trustAnchorVerifier = TrustAnchorVerifier.createEmptyTrustAnchorVerifier();
		trustAnchorVerifier.setUseSunsetDate(false); // set to FALSE for offline processing
		if (originalTrustAnchorVerifier != null) {
			trustAnchorVerifier.setTrustedCertificateSource(originalTrustAnchorVerifier.getTrustedCertificateSource());
			trustAnchorVerifier.setAcceptRevocationUntrustedCertificateChains(originalTrustAnchorVerifier.isAcceptRevocationUntrustedCertificateChains());
			trustAnchorVerifier.setAcceptTimestampUntrustedCertificateChains(originalTrustAnchorVerifier.isAcceptTimestampUntrustedCertificateChains());
		}
		return trustAnchorVerifier;
	}

	/**
	 * This method builds a local copy of a {@code CertificateVerifier} used by a signature validation process
	 *
	 * @return {@link CertificateVerifier}
	 */
	public CertificateVerifier buildCompleteCopyForValidation() {
		CertificateVerifier copy = buildCompleteCopy();
		copy.setRevocationFallback(true);
		return copy;
	}
	
}
