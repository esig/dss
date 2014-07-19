/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.crl;

import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * This class if a basic skeleton that is able to retrieve the needed CRL data from a list. The child need to retrieve
 * the list of wrapped CRLs.
 *
 * @version $Revision$ - $Date$
 */

public abstract class OfflineCRLSource extends CommonCRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineCRLSource.class);

	/**
	 * List of contained {@code X509CRL}s. One CRL list contains many CRLToken(s).
	 */
	protected List<X509CRL> x509CRLList;

	protected HashMap<CertificateToken, CRLToken> validCRLTokenList = new HashMap<CertificateToken, CRLToken>();

	protected HashMap<X509CRL, CRLValidity> crlIssuers = new HashMap<X509CRL, CRLValidity>();

	@Override
	final public CRLToken findCrl(final CertificateToken certificateToken) {

		final CRLToken validCRLToken = validCRLTokenList.get(certificateToken);
		if (validCRLToken != null) {

			return validCRLToken;
		}
		final CertificateToken issuerToken = certificateToken.getIssuerToken();
		if (issuerToken == null) {

			throw new DSSNullException(CertificateToken.class, "issuerToken");
		}

		CRLValidity bestCRLValidity = null;
		Date bestX509UpdateDate = null;

		for (final X509CRL x509CRL : x509CRLList) {

			CRLValidity crlValidity = crlIssuers.get(x509CRL);
			if (crlValidity == null) {

				crlValidity = isValidCRL(x509CRL, issuerToken);
				if (crlValidity.isValid()) {

					crlIssuers.put(x509CRL, crlValidity);
				}
			}
			if (crlValidity != null) {

				if (issuerToken.equals(crlValidity.issuerToken) && crlValidity.isValid()) {

					final Date thisUpdate = x509CRL.getThisUpdate();
					if (bestX509UpdateDate == null || thisUpdate.after(bestX509UpdateDate)) {

						bestCRLValidity = crlValidity;
						bestX509UpdateDate = thisUpdate;
					}
				}
			}
		}
		if (bestCRLValidity == null) {
			return null;
		}
		final CRLToken crlToken = new CRLToken(certificateToken, bestCRLValidity);
		validCRLTokenList.put(certificateToken, crlToken);
		return crlToken;
	}

	/**
	 * Retrieves the list of CRLTokens contained in the source. If this method is implemented for a signature source than the
	 * list of encapsulated CRLTokens in this signature is returned.<br>
	 * 102 853: Null is returned if there is no CRL data in the signature.
	 *
	 * @return
	 */
	public List<CRLToken> getContainedCRLTokens() {

		final Collection<CRLToken> values = validCRLTokenList.values();
		final ArrayList<CRLToken> crlTokenArrayList = new ArrayList<CRLToken>(values);
		return crlTokenArrayList;
	}

	public List<X509CRL> getContainedX509CRLs() {

		final List<X509CRL> x509CRLs = Collections.unmodifiableList(x509CRLList);
		return x509CRLs;
	}
}
