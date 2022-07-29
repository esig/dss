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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 * Allows storing and retrieving of revocation data to/from a repository
 * (e.g. database)
 *
 * @param <R> {@code CRL} or {@code OCSP}
 */
public abstract class RepositoryRevocationSource<R extends Revocation> implements RevocationSource<R> {

	private static final Logger LOG = LoggerFactory.getLogger(RepositoryRevocationSource.class); 

	private static final long serialVersionUID = 8116937707098957391L;

	/**
	 * Data source used to access a revocation token that is not present in the repository
	 */
	protected OnlineRevocationSource<R> proxiedSource;

	/**
	 * Default cache delay in case of null nextUpdate in the revocation data
	 */
	private Long defaultNextUpdateDelay;
	
	/**
	 * Maximum cache delay for the revocation data
	 */
	private Long maxNextUpdateDelay;

	/**
	 * If true, removes revocation tokens from DB with nextUpdate before the current date
	 */
	private boolean removeExpired = true;

	/**
	 * Default constructor instantiating object with null values
	 */
	protected RepositoryRevocationSource() {
	}
	
	/**
	 * Initialize a list of revocation token keys {@link String} from the given {@link CertificateToken}
	 *
	 * @param certificateToken {@link CertificateToken}
	 * @return list of {@link String} revocation keys
	 */
	protected abstract List<String> initRevocationTokenKeys(CertificateToken certificateToken);
	
	/**
	 * Finds a RevocationToken in the cache
	 *
	 * @param key
	 *            the key {@link String}
	 * @param certificateToken
	 *            {@link CertificateToken}
	 * @param issuerCertToken
	 *            {@link CertificateToken}
	 * @return
	 * 		  {@link RevocationToken} object
	 */
	protected abstract RevocationToken<R> findRevocation(final String key, CertificateToken certificateToken,
														 CertificateToken issuerCertToken);
	
	/**
	 * Inserts a new RevocationToken into the cache
	 *
	 * @param revocationKey
	 *            {@link String}
	 * @param token
	 *            {@link RevocationToken}
	 */
	protected abstract void insertRevocation(final String revocationKey, final RevocationToken<R> token);
	
	/**
	 * Updates the RevocationToken into cache
	 *
	 * @param revocationKey
	 *            {@link String}
	 * @param token
	 *            {@link RevocationToken}
	 */
	protected abstract void updateRevocation(final String revocationKey, final RevocationToken<R> token);

	/**
	 * Removes the RevocationToken from cache with the given key
	 *
	 * @param revocationKey
	 *            {@link String}
	 */
	protected abstract void removeRevocation(final String revocationKey);
	
	/**
	 * Sets the default next update delay for the cached files in seconds. If
	 * more time has passed from the revocation token's thisUpdate and next update
	 * time is not specified, then a fresh copy is downloaded and cached, otherwise
	 * a cached copy is used.
	 * 
	 * {@code
	 *  If revocation.nextUpdate = null, then nextUpdate = revocation.thisUpdate + defaultNextUpdateDelay
	 *}
	 * 
	 * @param defaultNextUpdateDelay
	 *                               long value (seconds)
	 */
	public void setDefaultNextUpdateDelay(final Long defaultNextUpdateDelay) {
		this.defaultNextUpdateDelay = defaultNextUpdateDelay == null ? null : defaultNextUpdateDelay * 1000; // to milliseconds
	}

	/**
	 * Sets the maximum allowed nextUpdate delay for cached files in seconds.
	 * Allows to force refresh in case of long periods between revocation
	 * publication (eg : 6 months for ARL).
	 * 
	 * {@code
	 *  If revocation.nextUpdate > revocation.thisUpdate + maxNextUpdateDelay, then nextUpdate = revocation.thisUpdate + maxNextUpdateDelay
	 *}
	 * 
	 * @param maxNextUpdateDelay
	 *                          long value (seconds)
	 */
	public void setMaxNextUpdateDelay(final Long maxNextUpdateDelay) {
		this.maxNextUpdateDelay = maxNextUpdateDelay == null ? null : maxNextUpdateDelay * 1000; // to milliseconds
	}

	/**
	 * The proxied revocation source to be called if the data is not available in
	 * the cache
	 * 
	 * @param proxiedSource
	 *                      the proxiedSource to set
	 */
	public void setProxySource(final OnlineRevocationSource<R> proxiedSource) {
		this.proxiedSource = proxiedSource;
	}
	
	/**
	 * Sets whether the proxied revocation source to be called if the data is not available in the cache
	 *
	 * @param removeExpired
	 *            the removeExpired to set
	 */
	public void setRemoveExpired(boolean removeExpired) {
		this.removeExpired = removeExpired;
	}
	
	@Override
	public RevocationToken<R> getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) {
		return getRevocationToken(certificateToken, issuerCertificateToken, false);
	}

	/**
	 * Retrieves a revocation token for the given {@link CertificateToken}
	 * 
	 * @param certificateToken
	 *                               {@link CertificateToken}
	 * @param issuerCertificateToken
	 *                               {@link CertificateToken} of the issuer of
	 *                               certificateToken
	 * @param forceRefresh
	 *                               if true, explicitly skips the cache
	 * @return {@link RevocationToken}
	 */
	public RevocationToken<R> getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerCertificateToken, boolean forceRefresh) {
		if ((certificateToken == null) || (issuerCertificateToken == null)) {
			LOG.warn("Certificate token or issuer's certificate token is null. Cannot get a revocation token!");
			return null;
		}

		final List<String> keys = initRevocationTokenKeys(certificateToken);
		if (forceRefresh) {
			LOG.info("Cache is skipped to retrieve the revocation token for certificate with Id '{}'",
					certificateToken.getDSSIdAsString());
		} else {
			RevocationToken<R> cachedRevocationToken = extractRevocationFromCacheSource(certificateToken, issuerCertificateToken, keys);
			if (cachedRevocationToken != null) {
				return cachedRevocationToken;
			}
		}
		return extractAndInsertRevocationTokenFromProxiedSource(certificateToken, issuerCertificateToken, keys);
	}
	
	/**
	 * Extracts a {@link RevocationToken} from Cache Source if the relevant entry is stored, null otherwise
	 * 
	 * @param certificateToken {@link CertificateToken} to extract the revocation token for
	 * @param issuerCertificateToken {@link CertificateToken} of the issuer
	 * @param keys - list of keys, that can be used as unique identifications of the revocation entry
	 * @return {@link RevocationToken}
	 */
	private RevocationToken<R> extractRevocationFromCacheSource(final CertificateToken certificateToken,
			final CertificateToken issuerCertificateToken, 
			List<String> keys) {
		Iterator<String> keyIterator = keys.iterator();
		while (keyIterator.hasNext()) {
			String key = keyIterator.next();
			final RevocationToken<R> revocationToken = findRevocation(key, certificateToken, issuerCertificateToken);
			if (revocationToken != null) {
				if (isNotExpired(revocationToken, issuerCertificateToken)) {
					LOG.info("Revocation token for certificate with Id '{}' has been loaded from the cache",
							certificateToken.getDSSIdAsString());
					return revocationToken;
				} else {
					LOG.debug("Revocation token is expired");
					if (removeExpired) {
						removeRevocation(key);
						keyIterator.remove();
					}
				}
			} else {
				keyIterator.remove();
			}
		}
		return null;
	}
	
	/**
	 * Extracts a {@link RevocationToken} from the defined proxiedSource and inserts/updates its
	 * in the cache source if required.
	 *
	 * @param certificateToken {@link CertificateToken} to extract the revocation token for
	 * @param issuerCertificateToken {@link CertificateToken} of the issuer
	 * @param keys - list of keys that can be used as unique identifications of the revocation entry
	 * @return {@link RevocationToken}
	 */
	private RevocationToken<R> extractAndInsertRevocationTokenFromProxiedSource(final CertificateToken certificateToken,
			final CertificateToken issuerCertificateToken, 
			List<String> keys) {
		if (proxiedSource == null) {
			LOG.warn("Proxied revocation source is not initialized for the called RevocationSource!");
			return null;
		}

		RevocationToken<R> newToken = null;

		OnlineRevocationSource.RevocationTokenAndUrl<R> revocationTokenAndUrl =
				proxiedSource.getRevocationTokenAndUrl(certificateToken, issuerCertificateToken);
		if (revocationTokenAndUrl != null) {
			newToken = revocationTokenAndUrl.getRevocationToken();
			if (newToken.isValid()) {
				String revocationTokenKey = getRevocationTokenKey(certificateToken, revocationTokenAndUrl.getUrlString());
				if (!keys.contains(revocationTokenKey)) {
					insertRevocation(revocationTokenKey, newToken);
					LOG.info("Revocation token for certificate '{}' is added into the cache", certificateToken.getDSSIdAsString());
				} else {
					updateRevocation(revocationTokenKey, newToken);
					LOG.info("Revocation token for certificate '{}' is updated in the cache", certificateToken.getDSSIdAsString());
				}
			}
		}
		return newToken;
	}

	/**
	 * Gets a unique revocation token identifier used to store the revocation token
	 * for this {@code certificateToken} within a repository
	 *
	 * @param certificateToken {@link CertificateToken}
	 * @param urlString {@link String} representing a URL used to download the revocation token from
	 * @return {@link String} revocation token key
	 */
	protected abstract String getRevocationTokenKey(CertificateToken certificateToken, String urlString);

	/**
	 * Checks if the nextUpdate date is currently valid with respect of
	 * nextUpdateDelay and maxNexUpdateDelay parameters.
	 * 
	 * @param revocationToken
	 *              {@code CRLToken} or {@code OCSPToken}
	 * @param certificateTokenIssuer
	 *              issuer of a CertificateToken to check the revocation for
	 * @return TRUE if the token is still valid, FALSE otherwise
	 */
	private boolean isNotExpired(RevocationToken<R> revocationToken, CertificateToken certificateTokenIssuer) {
		Date validationDate = new Date();
		
		Date nextUpdate = revocationToken.getNextUpdate();
		if (nextUpdate == null) {
			// check the validity of the issuer certificate
			CertificateToken certificateToken = revocationToken.getIssuerCertificateToken();
			if (certificateToken == null) {
				certificateToken = certificateTokenIssuer;
			}
			if (!certificateToken.isValidOn(validationDate)) {
				return false;
			}
		}
		
		// check the validity of the revocation token itself
		final Date thisUpdate = revocationToken.getThisUpdate();
		if (nextUpdate == null && defaultNextUpdateDelay != null && thisUpdate != null) {
			nextUpdate = new Date(thisUpdate.getTime() + defaultNextUpdateDelay);
		}
		if (nextUpdate != null) {
			if (maxNextUpdateDelay != null && thisUpdate != null) {
				Date maxNextUpdate = new Date(thisUpdate.getTime() + maxNextUpdateDelay);
				if (nextUpdate.after(maxNextUpdate)) {
					nextUpdate = maxNextUpdate;
				}
			}
			return nextUpdate.after(validationDate);
		}
		
		return false;
	}

}
