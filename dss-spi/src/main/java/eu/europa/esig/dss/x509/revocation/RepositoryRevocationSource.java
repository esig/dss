package eu.europa.esig.dss.x509.revocation;

import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPToken;

public abstract class RepositoryRevocationSource<T extends RevocationToken> implements RevocationSource<T> {

	private static final Logger LOG = LoggerFactory.getLogger(RepositoryRevocationSource.class); 

	private static final long serialVersionUID = 8116937707098957391L;

	protected OnlineRevocationSource<T> proxiedSource;

	/**
	 * Default cache delay in case of null nextUpdate in the revocation data
	 */
	private Long defaultNextUpdateDelay;
	
	/**
	 * Maximum cache delay for the revocation data
	 */
	private Long maxNexUpdateDelay;

	/**
	 * If true, removes revocation tokens from DB with nextUpdate before the current date
	 */
	private boolean removeExpired = true;
	
	/**
	 * Initialize a list of revocation token keys {@link String} from the given {@link CertificateToken}
	 * @param certificateToken {@link CertificateToken}
	 * @return list of {@link String} revocation keys
	 */
	public abstract List<String> initRevocationTokenKey(CertificateToken certificateToken);
	
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
	protected abstract T findRevocation(String key, CertificateToken certificateToken, CertificateToken issuerCertToken);
	
	/**
	 * Inserts a new RevocationToken into the cache
	 *
	 * @param token
	 *            {@link RevocationToken}
	 */
	protected abstract void insertRevocation(T token);
	
	/**
	 * Updates the RevocationToken into cache
	 *
	 * @param token
	 *            {@link RevocationToken}
	 */
	protected abstract void updateRevocation(T token);

	/**
	 * Removes the RevocationToken from cache
	 *
	 * @param token
	 *            {@link RevocationToken}
	 */
	protected abstract void removeRevocation(T token);
	
	/**
	 * Sets the default next update delay for the cached files in milliseconds. If
	 * more time has passed from the revocation token's thisUpdate and next update
	 * time is not specified, then a fresh copy is downloaded and cached, otherwise
	 * a cached copy is used.
	 * 
	 * {@code
	 *  If revocation.nextUpdate = null, then nextUpdate = revocation.thisUpdate + defaultNextUpdateDelay
	 *}
	 * 
	 * @param defaultNextUpdateDelay
	 *                               long value (milli seconds)
	 */
	public void setDefaultNextUpdateDelay(final Long defaultNextUpdateDelay) {
		this.defaultNextUpdateDelay = defaultNextUpdateDelay;
	}

	/**
	 * Sets the maximum allowed nextUpdate delay for cached files in milliseconds.
	 * Allows to force refresh in case of long periods between revocation
	 * publication (eg : 6 months for ARL).
	 * 
	 * {@code
	 *  If revocation.nextUpdate > revocation.thisUpdate + maxNexUpdateDelay, then nextUpdate = revocation.thisUpdate + maxNexUpdateDelay
	 *}
	 * 
	 * @param maxNexUpdateDelay
	 *                          long value (milli seconds)
	 */
	public void setMaxNexUpdateDelay(final Long maxNexUpdateDelay) {
		this.maxNexUpdateDelay = maxNexUpdateDelay;
	}

	/**
	 * The proxied revocation source to be called if the data is not available in
	 * the cache
	 * 
	 * @param proxiedSource
	 *                      the proxiedSource to set
	 */
	public void setProxySource(final OnlineRevocationSource<T> proxiedSource) {
		this.proxiedSource = proxiedSource;
	}
	
	/**
	 * @param removeExpired
	 *            the removeExpired to set
	 */
	public void setRemoveExpired(boolean removeExpired) {
		this.removeExpired = removeExpired;
	}
	
	/**
	 * Retrieves a revocation token for the given {@link CertificateToken}
	 * 
	 * @param certificateToken
	 *                               {@link CertificateToken}
	 * @param issuerCertificateToken
	 *                               {@link CertificateToken} of the issuer of
	 *                               certificateToken
	 */
	@Override
	public T getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) {
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
	 */
	public T getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerCertificateToken, boolean forceRefresh) {
		if ((certificateToken == null) || (issuerCertificateToken == null)) {
			LOG.warn("Certificate token or issuer's certificate token is null. Cannot get a revocation token!");
			return null;
		}

		final List<String> keys = initRevocationTokenKey(certificateToken);
		if (forceRefresh) {
			LOG.info("Cache is skipped to retrieve the revocation token for certificate '{}'", certificateToken.getDSSIdAsString());
		} else {
			T cachedRevocationToken = extractRevocationFromCacheSource(certificateToken, issuerCertificateToken, keys);
			if (cachedRevocationToken != null) {
				return cachedRevocationToken;
			}
		}
		return extractAndInsertRevocationTokenFromProxiedSource(certificateToken, issuerCertificateToken, keys);
	}
	
	/**
	 * Extracts a {@link RevocationToken} from Cache Source if the relevant entry is stored, null otherwise
	 * @param certificateToken {@link CertificateToken} to extract the revocation token for
	 * @param issuerCertificateToken {@link CertificateToken} of the issuer
	 * @param keys - list of keys, that can be used as unique identifications of the revocation entry
	 * @return {@link RevocationToken}
	 */
	private T extractRevocationFromCacheSource(final CertificateToken certificateToken, final CertificateToken issuerCertificateToken, 
			List<String> keys) {
		Iterator<String> keyIterator = keys.iterator();
		while (keyIterator.hasNext()) {
			String key = keyIterator.next();
			final T revocationToken = findRevocation(key, certificateToken, issuerCertificateToken);
			if (revocationToken != null) {
				if (isNotExpired(revocationToken)) {
					LOG.info("Revocation token for certificate '{}' is loaded from the cache", certificateToken.getDSSIdAsString());
					return revocationToken;
				} else {
					LOG.debug("Revocation token is expired");
					if (removeExpired) {
						removeRevocation(revocationToken);
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
	 * Extracts a {@link RevocationToken} from the defined proxiedSource and inserts/updates its in the cache Source if needed
	 * @param certificateToken {@link CertificateToken} to extract the revocation token for
	 * @param issuerCertificateToken {@link CertificateToken} of the issuer
	 * @param keys - list of keys, that can be used as unique identifications of the revocation entry
	 * @return {@link RevocationToken}
	 */
	private T extractAndInsertRevocationTokenFromProxiedSource(final CertificateToken certificateToken, final CertificateToken issuerCertificateToken, 
			List<String> keys) {
		if (proxiedSource == null) {
			LOG.warn("Proxied revocation source is not initialized for the called RevocationSource!");
			return null;
		}
		final T newToken = proxiedSource.getRevocationToken(certificateToken, issuerCertificateToken);
		if ((newToken != null) && newToken.isValid()) {
			if (!keys.contains(newToken.getRevocationTokenKey())) {
				LOG.info("Revocation token for certificate '{}' is added in the cache", certificateToken.getDSSIdAsString());
				insertRevocation(newToken);
			} else {
				LOG.info("Revocation token for certificate '{}' is updated in the cache", certificateToken.getDSSIdAsString());
				updateRevocation(newToken);
			}
		}
		return newToken;
	}

	/**
	 * Checks if the nextUpdate date is currently valid with respect of
	 * nextUpdateDelay and maxNexUpdateDelay parameters.
	 * 
	 * @param token
	 *              {@link CRLToken} or {@link OCSPToken}
	 * @return TRUE if the token is still valid, FALSE otherwise
	 */
	private boolean isNotExpired(T token) {
		final Date thisUpdate = token.getThisUpdate();
		if (thisUpdate == null) {
			return false;
		}

		Date nextUpdate = token.getNextUpdate();
		if (nextUpdate == null && defaultNextUpdateDelay != null) {
			nextUpdate = new Date(thisUpdate.getTime() + defaultNextUpdateDelay);
		}
		if (nextUpdate != null) {

			if (maxNexUpdateDelay != null) {
				Date maxNextUpdate = new Date(thisUpdate.getTime() + maxNexUpdateDelay);
				if (nextUpdate.after(maxNextUpdate)) {
					nextUpdate = maxNextUpdate;
				}
			}

			return nextUpdate.after(new Date());
		}
		return false;
	}

}
