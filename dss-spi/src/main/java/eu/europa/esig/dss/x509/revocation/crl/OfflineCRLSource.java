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
package eu.europa.esig.dss.x509.revocation.crl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.identifier.CRLBinaryIdentifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationOrigin;

/**
 * This class if a basic skeleton that is able to retrieve needed CRL data from
 * the contained list. The child need to retrieve the list of wrapped CRLs.
 */
@SuppressWarnings("serial")
public abstract class OfflineCRLSource implements CRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineCRLSource.class);

	/**
	 * This {@code List} contains all collected CRL binaries.
	 */
	protected final List<CRLBinaryIdentifier> crlsBinaryList = new ArrayList<CRLBinaryIdentifier>();

	/**
	 * This {@code HashMap} contains the {@code CRLValidity} object for each
	 * pair of crl's id + issuer token id {@code String}. It is used for performance reasons.
	 */
	private Map<String, CRLValidity> crlValidityMap = new HashMap<String, CRLValidity>();

	private Map<CertificateToken, CRLToken> validCRLTokenList = new HashMap<CertificateToken, CRLToken>();

	@Override
	public final CRLToken getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerToken) {
		if (certificateToken == null) {
			throw new NullPointerException();
		}

		final CRLToken validCRLToken = validCRLTokenList.get(certificateToken);
		if (validCRLToken != null) {
			return validCRLToken;
		}

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
		storeCRLToken(bestCRLValidity.getCrlBinaryIdentifier(), crlToken);
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

		for (CRLBinaryIdentifier crlEntry : crlsBinaryList) {
			final CRLValidity crlValidity = getCrlValidity(crlEntry, issuerToken);
			if (crlValidity == null || !crlValidity.isValid()) {
				continue;
			}
			// check the overlapping of the [thisUpdate, nextUpdate] from the CRL and
			// [notBefore, notAfter] from the X509Certificate
			final Date thisUpdate = crlValidity.getThisUpdate();
			final Date nextUpdate = crlValidity.getNextUpdate();
			final Date notAfter = certificateToken.getNotAfter();
			final Date notBefore = certificateToken.getNotBefore();
			boolean periodAreIntersecting = thisUpdate.before(notAfter) && (nextUpdate != null && nextUpdate.after(notBefore));
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
	 * {@code X509CRL}. The check of the validity of the CRL is performed.
	 * 
	 * @param key
	 *            the key to use in maps
	 * @param crlBinaries
	 *            the CRL binaries to be checked
	 * @param issuerToken
	 *            {@code CertificateToken} issuer of the CRL
	 * @return returns updated {@code CRLValidity} object
	 */
	private synchronized CRLValidity getCrlValidity(final CRLBinaryIdentifier crlBinary, final CertificateToken issuerToken) {
		String crlValidityKey = getCrlValidityKey(crlBinary, issuerToken);
		CRLValidity crlValidity = crlValidityMap.get(crlValidityKey);
		if (crlValidity == null) {
			try {
				crlValidity = CRLUtils.buildCrlValidity(crlBinary, issuerToken);
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
	 * Builds {@code CRLBinaryIdentifier} from the given binaries and returns the identifier object
	 * @param binaries byte array to compute identifier from
	 * @param origin {@link RevocationOrigin} indicating the correct list to store the value
	 * @return computed {@link CRLBinaryIdentifier}
	 */
	protected CRLBinaryIdentifier addCRLBinary(byte[] binaries, RevocationOrigin origin) {
		CRLBinaryIdentifier crlBinary = CRLBinaryIdentifier.build(binaries, origin);
		addCRLBinary(crlBinary, origin);
		return crlBinary;
	}

	protected void addCRLBinary(CRLBinaryIdentifier crlBinary, RevocationOrigin origin) {
		int ii = crlsBinaryList.indexOf(crlBinary);
		if (ii > -1) {
			CRLBinaryIdentifier storedCrlBinary = crlsBinaryList.get(ii);
			storedCrlBinary.addOrigin(origin);
		} else {
			crlsBinaryList.add(crlBinary);
		}
	}
	
	/**
	 * Computes an issuer-dependent key for {@code crlValidityMap}
	 * @param crlBinary {@link CRLBinaryIdentifier} of the CRL Entry
	 * @param issuerToken {@link CertificateToken} of issuer
	 * @return a new {@link String} key for CrlValidity map
	 */
	private String getCrlValidityKey(final CRLBinaryIdentifier crlBinary, final CertificateToken issuerToken) {
		return crlBinary.asXmlId() + issuerToken.getDSSIdAsString();
	}

	/**
	 * @return unmodifiable {@code Collection}
	 */
	public Collection<CRLBinaryIdentifier> getContainedX509CRLs() {
		Collection<CRLBinaryIdentifier> crlBinaries = new ArrayList<CRLBinaryIdentifier>();
		if (!isEmpty()) {
			for (CRLBinaryIdentifier crlBinary : crlsBinaryList) {
				crlBinaries.add(crlBinary);
			}
		}
		return Collections.unmodifiableCollection(crlBinaries);
	}
	
	public boolean isEmpty() {
		return Utils.isCollectionEmpty(crlsBinaryList);
	}
	
	protected void storeCRLToken(final CRLBinaryIdentifier crlBinary, final CRLToken crlToken) {
		// not implemented by default
	}
	
	/**
	 * Returns all found in DSS and VRI dictionaries {@link CRLBinaryIdentifier}s
	 * @return collection of {@link CRLBinaryIdentifier}s
	 */
	public Collection<CRLBinaryIdentifier> getAllCRLIdentifiers() {
		return crlsBinaryList;
	}

	/**
	 * Returns the identifier related to the {@code crlRef}
	 * @param crlRef {@link CRLRef} to find identifier for
	 * @return {@link CRLBinaryIdentifier} for the reference
	 */
	public CRLBinaryIdentifier getIdentifier(CRLRef crlRef) {
		return getIdentifier(crlRef.getDigest());
	}
	
	/**
	 * Returns the identifier related for the provided digest of the reference
	 * @param digest {@link Digest} of the reference
	 * @return {@link CRLBinaryIdentifier} for the reference
	 */
	public CRLBinaryIdentifier getIdentifier(Digest digest) {
		for (CRLBinaryIdentifier crlBinary : crlsBinaryList) {
			byte[] digestValue = crlBinary.getDigestValue(digest.getAlgorithm());
			if (Arrays.equals(digest.getValue(), digestValue)) {
				return crlBinary;
			}
		}
		return null;
	}

}
