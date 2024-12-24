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
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSourceAlternateUrlsSupport;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;

import java.util.List;

/**
 * This class allows to inject alternative urls to collect revocation data. This
 * is mainly used to collect revocations from discovered urls in the trusted
 * lists (supplyPoint).
 * 
 * @param <R> a sub-class of {@code Revocation}
 */
public class AlternateUrlsSourceAdapter<R extends Revocation> implements RevocationSourceAlternateUrlsSupport<R> {

	private static final long serialVersionUID = 3375119421036319160L;

	/** The source to extract revocation tokens */
	private final RevocationSourceAlternateUrlsSupport<R> wrappedSource;

	/** List of alternative URLs */
	private final List<String> alternateUrls;

	/**
	 * Default constructor
	 *
	 * @param source {@link RevocationSourceAlternateUrlsSupport}
	 * @param alternateUrls a list of {@link String} access points
	 */
	public AlternateUrlsSourceAdapter(RevocationSourceAlternateUrlsSupport<R> source, List<String> alternateUrls) {
		this.wrappedSource = source;
		this.alternateUrls = alternateUrls;
	}

	@Override
	public RevocationToken<R> getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		return wrappedSource.getRevocationToken(certificateToken, issuerCertificateToken, alternateUrls);
	}

	@Override
	public RevocationToken<R> getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken, List<String> alternativeUrls) {
		return wrappedSource.getRevocationToken(certificateToken, issuerCertificateToken, alternativeUrls);
	}

}
