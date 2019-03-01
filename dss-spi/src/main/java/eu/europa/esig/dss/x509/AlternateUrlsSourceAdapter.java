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

import java.util.List;

import eu.europa.esig.dss.x509.revocation.RevocationSourceAlternateUrlsSupport;

/**
 * This class allows to inject alternative urls to collect revocation data. This
 * is mainly used to collect revocations from discovered urls in the trusted
 * lists (supplyPoint).
 * 
 * @param <T>
 *        a sub-class of {@code RevocationToken}
 */
public class AlternateUrlsSourceAdapter<T extends RevocationToken> implements RevocationSourceAlternateUrlsSupport<T> {

	private static final long serialVersionUID = 3375119421036319160L;

	private final RevocationSourceAlternateUrlsSupport<T> wrappedSource;
	private final List<String> alternateUrls;

	public AlternateUrlsSourceAdapter(RevocationSourceAlternateUrlsSupport<T> source, List<String> alternateUrls) {
		this.wrappedSource = source;
		this.alternateUrls = alternateUrls;
	}

	@Override
	public T getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		return wrappedSource.getRevocationToken(certificateToken, issuerCertificateToken, alternateUrls);
	}

	@Override
	public T getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken, List<String> alternativeUrls) {
		return wrappedSource.getRevocationToken(certificateToken, issuerCertificateToken, alternativeUrls);
	}

}
