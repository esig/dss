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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class if a basic skeleton that is able to retrieve needed CRL data from
 * the contained list. The child need to retrieve the list of wrapped CRLs.
 */
@SuppressWarnings("serial")
public abstract class OfflineCRLSource implements CRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(OfflineCRLSource.class);

	/**
	 * This {@code Map} contains all collected CRL binaries with a set of their origins
	 */
	private final Map<CRLBinary, Set<RevocationOrigin>> crlBinaryOriginsMap = new HashMap<CRLBinary, Set<RevocationOrigin>>();

	/**
	 * This {@code HashMap} contains the {@code CRLValidity} object for each
	 * pair of crl's id + issuer token id {@code String}. It is used for performance reasons.
	 */
	private Map<String, CRLValidity> crlValidityMap = new HashMap<String, CRLValidity>();

	private Map<CertificateToken, CRLToken> validCRLTokenList = new HashMap<CertificateToken, CRLToken>();

	@Override
	public final CRLToken getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerToken) {
		Objects.requireNonNull(certificateToken, "The certificate to be verified cannot be null");

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
		crlToken.setOrigins(getRevocationOrigins(bestCRLValidity.getCrlBinaryIdentifier()));
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

		for (CRLBinary crlEntry : crlBinaryOriginsMap.keySet()) {
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
	 * Builds {@code CRLBinaryIdentifier} from the given binaries and returns the identifier object
	 * @param binaries byte array to compute identifier from
	 * @param origin {@link RevocationOrigin} indicating the correct list to store the value
	 * @return computed {@link CRLBinary}
	 */
	protected CRLBinary addCRLBinary(byte[] binaries, RevocationOrigin origin) {
		CRLBinary crlBinary = new CRLBinary(binaries);
		addCRLBinary(crlBinary, origin);
		return crlBinary;
	}

	protected void addCRLBinary(CRLBinary crlBinary, RevocationOrigin origin) {
		Set<RevocationOrigin> origins = crlBinaryOriginsMap.get(crlBinary);
		if (origins == null) {
			origins = new HashSet<RevocationOrigin>();
			crlBinaryOriginsMap.put(crlBinary, origins);
		}
		origins.add(origin);
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

	/**
	 * @return unmodifiable {@code Collection}
	 */
	public Collection<CRLBinary> getCRLBinaryList() {
		return Collections.unmodifiableCollection(crlBinaryOriginsMap.keySet());
	}

	/**
	 * Checks if the CRL Source is empty or not (crlBinaryOriginsMap)
	 * @return TRUE if the source is empty, FALSE otherwise
	 */
	public boolean isEmpty() {
		return Utils.isMapEmpty(crlBinaryOriginsMap);
	}
	
	protected void storeCRLToken(final CRLBinary crlBinary, final CRLToken crlToken) {
		// not implemented by default
	}

	/**
	 * Returns the identifier related to the {@code crlRef}
	 * @param crlRef {@link CRLRef} to find identifier for
	 * @return {@link CRLBinary} for the reference
	 */
	public CRLBinary getIdentifier(CRLRef crlRef) {
		return getIdentifier(crlRef.getDigest());
	}
	
	/**
	 * Returns the identifier related for the provided digest of the reference
	 * @param digest {@link Digest} of the reference
	 * @return {@link CRLBinary} for the reference
	 */
	public CRLBinary getIdentifier(Digest digest) {
		for (CRLBinary crlBinary : crlBinaryOriginsMap.keySet()) {
			byte[] digestValue = crlBinary.getDigestValue(digest.getAlgorithm());
			if (Arrays.equals(digest.getValue(), digestValue)) {
				return crlBinary;
			}
		}
		return null;
	}
	
	/**
	 * Returns a set of {@code RevocationOrigin}s for the given {@code crlBinary}
	 * @param crlBinary {@link CRLBinary} to get origins for
	 * @return set of {@link RevocationOrigin}s
	 */
	public Set<RevocationOrigin> getRevocationOrigins(CRLBinary crlBinary) {
		return crlBinaryOriginsMap.get(crlBinary);
	}

}
