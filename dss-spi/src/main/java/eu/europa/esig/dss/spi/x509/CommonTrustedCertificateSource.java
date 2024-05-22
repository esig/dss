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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.tsl.TrustProperties;

import java.util.Collections;
import java.util.List;

/**
 * This class represents the simple list of trusted certificates.
 *
 */
@SuppressWarnings("serial")
public class CommonTrustedCertificateSource extends CommonCertificateSource implements TrustedCertificateSource {

	/**
	 * Default constructor
	 */
	public CommonTrustedCertificateSource() {
		// empty
	}

	@Override
	public CertificateSourceType getCertificateSourceType() {
		return CertificateSourceType.TRUSTED_STORE;
	}

	/**
	 * This method allows to declare all certificates from a given certificate
	 * source as trusted.
	 *
	 * @param certificateSource
	 *                          the certificate source to be trusted
	 */
	public void importAsTrusted(final CertificateSource certificateSource) {
		final List<CertificateToken> certTokenList = certificateSource.getCertificates();
		for (final CertificateToken certToken : certTokenList) {
			addCertificate(certToken);
		}
	}

	/**
	 * Returns TrustProperties for the given certificate, when applicable
	 *
	 * @param token {@link CertificateToken}
	 * @return a list of {@link TrustProperties}
	 * @deprecated since DSS 6.1. To be removed. Please use implementation of
	 *         {@code eu.europa.esig.dss.spi.tsl.TrustPropertiesCertificateSource}, or
	 *         {@code eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource} class in order to provide trust services
	 */
	@Deprecated
	public List<TrustProperties> getTrustServices(CertificateToken token) {
		return Collections.emptyList();
	}

	@Override
	public List<String> getAlternativeOCSPUrls(CertificateToken trustAnchor) {
		return Collections.emptyList();
	}

	@Override
	public List<String> getAlternativeCRLUrls(CertificateToken trustAnchor) {
		return Collections.emptyList();
	}

	@Override
	public boolean isTrusted(CertificateToken certificateToken) {
		return isKnown(certificateToken);
	}

}
