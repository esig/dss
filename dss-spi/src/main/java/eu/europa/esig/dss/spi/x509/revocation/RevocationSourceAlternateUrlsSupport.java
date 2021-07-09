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
package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;

import java.util.List;

/**
 * This interface provides a method to retrieve a revocation data with a list of alternative URL access points
 *
 * @param <R> {@code Revocation}
 */
public interface RevocationSourceAlternateUrlsSupport<R extends Revocation> extends RevocationSource<R> {

	/**
	 * Gets an {@code RevocationToken} for the given certificate / issuer's
	 * certificate couple. The coherence between the response and the request is
	 * checked.
	 *
	 * @param certificateToken
	 *                               The {@code CertificateToken} for which the
	 *                               request is made
	 * @param issuerCertificateToken
	 *                               The {@code CertificateToken} which is the
	 *                               issuer of the certificateToken
	 * @param alternativeUrls
	 *                               The list of alternative urls to call
	 * @return {@code RevocationToken} containing information about the validity of
	 *         the cert
	 */
	RevocationToken<R> getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken,
										  List<String> alternativeUrls);
			
}
