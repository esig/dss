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
package eu.europa.esig.dss.validation;

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
			copy.setDefaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm());
			copy.setAIASource(certificateVerifier.getAIASource());
			copy.setCrlSource(certificateVerifier.getCrlSource());
			copy.setOcspSource(certificateVerifier.getOcspSource());
			copy.setRevocationDataLoadingStrategyBuilder(certificateVerifier.getRevocationDataLoadingStrategyBuilder());
			copy.setRevocationDataVerifier(certificateVerifier.getRevocationDataVerifier());
			copy.setCheckRevocationForUntrustedChains(certificateVerifier.isCheckRevocationForUntrustedChains());
			copy.setExtractPOEFromUntrustedChains(certificateVerifier.isExtractPOEFromUntrustedChains());
			copy.setAdjunctCertSources(certificateVerifier.getAdjunctCertSources());
			copy.setTrustedCertSources(certificateVerifier.getTrustedCertSources());
			copy.setAlertOnInvalidTimestamp(certificateVerifier.getAlertOnInvalidTimestamp());
			copy.setAlertOnMissingRevocationData(certificateVerifier.getAlertOnMissingRevocationData());
			copy.setAlertOnNoRevocationAfterBestSignatureTime(certificateVerifier.getAlertOnNoRevocationAfterBestSignatureTime());
			copy.setAlertOnRevokedCertificate(certificateVerifier.getAlertOnRevokedCertificate());
			copy.setAlertOnUncoveredPOE(certificateVerifier.getAlertOnUncoveredPOE());
			copy.setAlertOnExpiredSignature(certificateVerifier.getAlertOnExpiredSignature());
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
			offlineCertificateVerifier.setDefaultDigestAlgorithm(certificateVerifier.getDefaultDigestAlgorithm());
			offlineCertificateVerifier.setAdjunctCertSources(certificateVerifier.getAdjunctCertSources());
			offlineCertificateVerifier.setTrustedCertSources(certificateVerifier.getTrustedCertSources());
		}
		// disable alerting
		offlineCertificateVerifier.setAlertOnInvalidTimestamp(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnRevokedCertificate(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnUncoveredPOE(new SilentOnStatusAlert());
		offlineCertificateVerifier.setAlertOnExpiredSignature(new SilentOnStatusAlert());
		return offlineCertificateVerifier;
	}
	
}
