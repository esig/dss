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
import eu.europa.esig.dss.spi.client.http.DataLoader;

/**
 * Sub-interface for online sources of {@link RevocationToken}s
 *
 * @param <R> implementation of {@code Revocation} (CRL or OCSP) for the current revocation source
 */
public interface OnlineRevocationSource<R extends Revocation> extends RevocationSource<R> {
	
	/**
	 * Set the DataLoader to use for querying a revocation server.
	 *
	 * @param dataLoader
	 *            the component that allows to retrieve a revocation response using
	 *            HTTP.
	 */
	void setDataLoader(final DataLoader dataLoader);

	/**
	 * This method retrieves a {@code RevocationTokenAndUrl} for the certificateToken
	 *
	 * @param certificateToken
	 *                               The {@code CertificateToken} for which the
	 *                               request is made
	 * @param issuerToken
	 *                               The {@code CertificateToken} which is the
	 *                               issuer of the certificateToken
	 * @return an instance of {@code RevocationTokenAndUrl}
	 */
	RevocationTokenAndUrl<R> getRevocationTokenAndUrl(CertificateToken certificateToken, CertificateToken issuerToken);

	/**
	 * This class represents an online revocation source reply, containing the extracted {@code RevocationToken}
	 * and the URL {@code String} used to download the token from
	 *
	 * @param <R> implementation of {@code Revocation} (CRL or OCSP) for the current revocation source
	 */
	class RevocationTokenAndUrl<R extends Revocation> {

		/**
		 * Url used to obtain data.
		 */
		private final String urlString;

		/**
		 * The revocation token.
		 */
		private final RevocationToken<R> revocationToken;

		/**
		 * Default constructor
		 *
		 * @param urlString {@link String} URL used to download the revocation token
		 * @param revocationToken {@link RevocationToken} downloaded from the URL
		 */
		public RevocationTokenAndUrl(final String urlString, final RevocationToken<R> revocationToken) {
			this.urlString = urlString;
			this.revocationToken = revocationToken;
		}

		/**
		 * Gets the URL used to download the data
		 *
		 * @return {@link String}
		 */
		public String getUrlString() {
			return urlString;
		}

		/**
		 * Gets the downloaded {@code RevocationToken}
		 *
		 * @return {@link RevocationToken}
		 */
		public RevocationToken<R> getRevocationToken() {
			return revocationToken;
		}

	}

}
