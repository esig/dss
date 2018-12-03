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
package eu.europa.esig.dss.x509;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.ServiceInfo;

/**
 * This class represents the simple list of trusted certificates.
 *
 */
public class CommonTrustedCertificateSource extends CommonCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(CommonTrustedCertificateSource.class);

	public CommonTrustedCertificateSource() {
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

	public Set<ServiceInfo> getTrustServices(CertificateToken trustAnchor) {
		return Collections.emptySet();
	}

	public List<String> getAlternativeOCSPUrls(CertificateToken trustAnchor) {
		return Collections.emptyList();
	}

	public List<String> getAlternativeCRLUrls(CertificateToken trustAnchor) {
		return Collections.emptyList();
	}

}
