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
package eu.europa.esig.dss.x509.crl;

import java.security.cert.X509CRL;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class if a basic skeleton that is able to retrieve needed CRL data from
 * the contained list. The child need to retrieve the list of wrapped CRLs.
 */
public abstract class OfflineCRLSource implements CRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineCRLSource.class);

	/**
	 * List of contained {@code X509CRL}s. One CRL list contains many
	 * CRLToken(s).
	 */
	protected List<X509CRL> x509CRLList;

	protected HashMap<CertificateToken, CRLToken> validCRLTokenList = new HashMap<CertificateToken, CRLToken>();

	/**
	 * This {@code HashMap} contains the {@code CRLValidity} object for each
	 * {@code X509CRL}. It is used for performance reasons.
	 */
	protected Map<X509CRL, CRLValidity> crlValidityMap = new HashMap<X509CRL, CRLValidity>();

	@Override
	final public CRLToken findCrl(final CertificateToken certificateToken) {

		if (certificateToken == null) {

			throw new NullPointerException();
		}
		final CRLToken validCRLToken = validCRLTokenList.get(certificateToken);
		if (validCRLToken != null) {

			return validCRLToken;
		}
		final CertificateToken issuerToken = certificateToken.getIssuerToken();
		if (issuerToken == null) {

			throw new NullPointerException();
		}
		final CRLValidity bestCRLValidity = getBestCrlValidity(certificateToken, issuerToken);
		if (bestCRLValidity == null) {
			return null;
		}
		final CRLToken crlToken = new CRLToken(certificateToken, bestCRLValidity);
		validCRLTokenList.put(certificateToken, crlToken);
		return crlToken;
	}

	/**
	 * This method returns the best {@code CRLValidity} containing the most
	 * recent {@code X509CRL}.
	 *
	 * @param certificateToken
	 *            {@code CertificateToken} for with the CRL is issued
	 * @param issuerToken
	 *            {@code CertificateToken} representing the signing certificate
	 *            of the CRL
	 * @return {@code CRLValidity}
	 */
	private CRLValidity getBestCrlValidity(final CertificateToken certificateToken, final CertificateToken issuerToken) {

		CRLValidity bestCRLValidity = null;
		Date bestX509UpdateDate = null;

		for (final X509CRL x509CRL : x509CRLList) {

			final CRLValidity crlValidity = getCrlValidity(issuerToken, x509CRL);
			if (crlValidity == null) {
				continue;
			}
			if (issuerToken.equals(crlValidity.getIssuerToken()) && crlValidity.isValid()) {

				final Date thisUpdate = x509CRL.getThisUpdate();
				if (!certificateToken.hasExpiredCertOnCRLExtension()) {

					if (thisUpdate.before(certificateToken.getNotBefore()) || thisUpdate.after(certificateToken.getNotAfter())) {

						LOG.warn("The CRL was not issued during the validity period of the certificate! Certificate: "
								+ certificateToken.getDSSIdAsString());
						continue;
					}
				}
				if ((bestX509UpdateDate == null) || thisUpdate.after(bestX509UpdateDate)) {

					bestCRLValidity = crlValidity;
					bestX509UpdateDate = thisUpdate;
				}
			}
		}
		return bestCRLValidity;
	}

	/**
	 * This method returns {@code CRLValidity} object based on the given
	 * {@code X509CRL}. The check of the validity of the CRL is performed.
	 *
	 * @param issuerToken
	 *            {@code CertificateToken} issuer of the CRL
	 * @param x509CRL
	 *            {@code X509CRL} the validity to be checked
	 * @return returns updated {@code CRLValidity} object
	 */
	private synchronized CRLValidity getCrlValidity(final CertificateToken issuerToken, final X509CRL x509CRL) {

		CRLValidity crlValidity = crlValidityMap.get(x509CRL);
		if (crlValidity == null) {

			crlValidity = CRLUtils.isValidCRL(x509CRL, issuerToken);
			if (crlValidity.isValid()) {

				crlValidityMap.put(x509CRL, crlValidity);
			}
		}
		return crlValidity;
	}

	/**
	 * @return unmodifiable {@code List} of {@code X509CRL}s
	 */
	public List<X509CRL> getContainedX509CRLs() {

		final List<X509CRL> x509CRLs = Collections.unmodifiableList(x509CRLList);
		return x509CRLs;
	}
}
