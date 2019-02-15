package eu.europa.esig.dss.x509.revocation;

import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;

public abstract class RepositoryRevocationSource<T extends RevocationToken> implements RevocationSource<T> {

	private static final Logger LOG = LoggerFactory.getLogger(RepositoryRevocationSource.class); 

	private static final long serialVersionUID = 8116937707098957391L;

	protected OnlineSource<T> cachedSource;

	/**
	 * In case if the nextUpdate date is not specified in the response, this value used to compute the parameter,
	 * based on the delay from thisUpdate
	 */
	protected Long nextUpdateDelay;
	
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
	 * Sets the expiration time for the cached files in milliseconds. If more
	 * time has passed from the revocation token's thisUpdate and next update 
	 * time is not specified, then a fresh copy is downloaded and cached,
	 * otherwise a cached copy is used.
	 *
	 * @param cacheExpirationTimeInMilliseconds long value
	 */
	public void setCacheExpirationTime(final long cacheExpirationTimeInMilliseconds) {
		this.nextUpdateDelay = cacheExpirationTimeInMilliseconds;
	}

	/**
	 * @param cachedSource
	 *            the cachedSource to set
	 */
	public void setProxySource(final OnlineSource<T> cachedSource) {
		this.cachedSource = cachedSource;
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
	 * @param certificateToken {@link CertificateToken}
	 * @param issuerCertificateToken {@link CertificateToken} of the issuer of certificateToken
	 */
	@Override
	public T getRevocationToken(final CertificateToken certificateToken, final CertificateToken issuerCertificateToken) {
		if ((certificateToken == null) || (issuerCertificateToken == null)) {
			LOG.warn("Certificate token or issuer's certificate token is null. Cannot get a revocation token!");
			return null;
		}
		final List<String> keys = initRevocationTokenKey(certificateToken);
		Iterator<String> keyIterator = keys.iterator();
		while (keyIterator.hasNext()) {
			String key = keyIterator.next();
			final T revocationToken = findRevocation(key, certificateToken, issuerCertificateToken);
			if (revocationToken != null) {
				if (isNotExpired(revocationToken)) {
					LOG.debug("Revocation token is in cache");
					return revocationToken;
				} else {
					LOG.debug("Revocation token not valid, get new one...");
					if (removeExpired) {
						removeRevocation(revocationToken);
						keyIterator.remove();
					}
				}
			} else {
				keyIterator.remove();
			}
		}

		if (cachedSource == null) {
			LOG.warn("CachedSource is not initialized for the called RevocationSource!");
			return null;
		}
		final T newToken = cachedSource.getRevocationToken(certificateToken, issuerCertificateToken);
		if ((newToken != null) && newToken.isValid() && isNotExpired(newToken)) {
			if (!keys.contains(newToken.getRevocationTokenKey())) {
				LOG.info("RevocationToken '{}' is not in cache", newToken);
				insertRevocation(newToken);
			} else {
				updateRevocation(newToken);
			}
		}
		return newToken;
	}
	
	/**
	 * Checks if the nextUpdate date is currently valid with respect of nextUpdateDelay parameter
	 * if token does not contain the nextUpdate date
	 * @param token {@link CRLToken} or {@link OCSPToken}
	 * @return TRUE if the token is still valid, FALSE otherwise
	 */
	private boolean isNotExpired(T token) {
		Date nextUpdate = token.getNextUpdate();
		if (nextUpdate == null && nextUpdateDelay != null) {
			nextUpdate = new Date(token.getThisUpdate().getTime() + nextUpdateDelay);
		}
		if (nextUpdate != null) {
			return nextUpdate.after(new Date());
		}
		return false;
	}

}
