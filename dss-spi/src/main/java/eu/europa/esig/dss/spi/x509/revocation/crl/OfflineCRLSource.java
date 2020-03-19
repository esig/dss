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
package eu.europa.esig.dss.spi.x509.revocation.crl;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.model.identifier.MultipleDigestIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;

/**
 * This class if a basic skeleton that is able to retrieve needed CRL data from
 * the contained list. The child need to retrieve the list of wrapped CRLs.
 */
@SuppressWarnings("serial")
public abstract class OfflineCRLSource extends OfflineRevocationSource<CRL> implements RevocationSource<CRL> {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineCRLSource.class);

	protected OfflineCRLSource() {
		super(new CRLTokenRefMatcher());
	}

	/**
	 * This {@code HashMap} contains the {@code CRLValidity} object for each
	 * pair of crl's id + issuer token id {@code String}. It is used for performance reasons.
	 */
	private Map<String, CRLValidity> crlValidityMap = new HashMap<>();

	private Map<CertificateToken, CRLToken> validCRLTokenList = new HashMap<>();

	@Override
	public final RevocationToken<CRL> getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerToken) {
		Objects.requireNonNull(certificateToken, "The certificate to be verified cannot be null");

		final CRLToken validCRLToken = validCRLTokenList.get(certificateToken);
		if (validCRLToken != null) {
			return validCRLToken;
		}

		// Not found in cached results
		if (issuerToken == null) {
			return null;
		}

		final CRLValidity bestCRLValidity = getBestCrlValidityEntry(certificateToken, issuerToken);
		if (bestCRLValidity == null) {
			return null;
		}

		final CRLToken crlToken = new CRLToken(certificateToken, bestCRLValidity);
		validCRLTokenList.put(certificateToken, crlToken);
		// store tokens with different origins
		addRevocation(crlToken, bestCRLValidity.getCrlBinaryIdentifier());
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
	private CRLValidity getBestCrlValidityEntry(final CertificateToken certificateToken, final CertificateToken issuerToken) {

		CRLValidity bestCRLValidity = null;
		Date bestX509UpdateDate = null;

		for (MultipleDigestIdentifier binary : getCollectedBinaries()) {
			CRLBinary crlEntry = (CRLBinary) binary;
			final CRLValidity crlValidity = getCrlValidity(crlEntry, issuerToken);
			if (!crlValidity.isValid()) {
				continue;
			}
			// check the overlapping of the [thisUpdate, nextUpdate] from the CRL and
			// [notBefore, notAfter] from the X509Certificate
			final Date thisUpdate = crlValidity.getThisUpdate();
			final Date nextUpdate = crlValidity.getNextUpdate();
			final Date notAfter = certificateToken.getNotAfter();
			final Date notBefore = certificateToken.getNotBefore();
			boolean periodAreIntersecting = thisUpdate.compareTo(notAfter) <= 0 && (nextUpdate != null && nextUpdate.compareTo(notBefore) >= 0);
			if (!periodAreIntersecting) {
				LOG.warn("The CRL was not issued during the validity period of the certificate! Certificate: {}", certificateToken.getDSSIdAsString());
				continue;
			}
			if ((bestX509UpdateDate == null) || thisUpdate.after(bestX509UpdateDate)) {
				bestCRLValidity = crlValidity;
				bestX509UpdateDate = thisUpdate;
			}
		}
		return bestCRLValidity;
	}

	/**
	 * This method returns {@code CRLValidity} object based on the given
	 * {@code CRLBinary}. The check of the validity of the CRL is performed.
	 * 
	 * @param crlBinary   the CRL binaries to be checked
	 * @param issuerToken {@code CertificateToken} issuer of the CRL
	 * @return returns updated {@code CRLValidity} object
	 */
	private CRLValidity getCrlValidity(final CRLBinary crlBinary, final CertificateToken issuerToken) {
		String crlValidityKey = getCrlValidityKey(crlBinary, issuerToken);
		CRLValidity crlValidity = crlValidityMap.get(crlValidityKey);
		if (crlValidity == null) {
			try {
				crlValidity = CRLUtils.buildCRLValidity(crlBinary, issuerToken);
				if (crlValidity.isValid()) {
					crlValidityMap.put(crlValidityKey, crlValidity);
				}
			} catch (IOException e) {
				LOG.error("Unable to parse CRL", e);
			}
		}
		return crlValidity;
	}

	/**
	 * Computes an issuer-dependent key for {@code crlValidityMap}
	 * @param crlBinary {@link CRLBinary} of the CRL Entry
	 * @param issuerToken {@link CertificateToken} of issuer
	 * @return a new {@link String} key for CrlValidity map
	 */
	private String getCrlValidityKey(final CRLBinary crlBinary, final CertificateToken issuerToken) {
		return crlBinary.asXmlId() + issuerToken.getDSSIdAsString();
	}

}
