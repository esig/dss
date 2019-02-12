package eu.europa.esig.dss.x509.revocation;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;

public abstract class RepositoryRevocationSource<T extends RevocationToken> implements RevocationSource<T> {

	private static final Logger LOG = LoggerFactory.getLogger(RepositoryRevocationSource.class); 

	private static final long serialVersionUID = 8116937707098957391L;

	protected RevocationSource<T> cachedSource;

	protected Long cacheExpirationTime;
	
	/**
	 * Initialize a revocation token key {@link String} from the given {@link CertificateToken}
	 * @param certificateToken {@link CertificateToken}
	 * @param issuerCertificateToken {@link CertificateToken} of CA
	 * @return {@link String} revocation key
	 */
	public abstract String initRevocationTokenKey(CertificateToken certificateToken, CertificateToken issuerCertificateToken);
	
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
	public abstract T findRevocation(String key, CertificateToken certificateToken, CertificateToken issuerCertToken);
	
	/**
	 * Inserts a new RevocationToken into the cache
	 *
	 * @param key
	 *            the key {@link String}
	 * @param token
	 *            {@link RevocationToken}
	 */
	protected abstract void insertRevocation(String key, T token);
	
	/**
	 * Updates the RevocationToken into cache
	 *
	 * @param key
	 *            the key {@link String}
	 * @param token
	 *            {@link RevocationToken}
	 */
	protected abstract void updateRevocation(String key, T token);
	
	/**
	 * Sets the expiration time for the cached files in milliseconds. If more
	 * time has passed from the cache file's last modified time, then a fresh
	 * copy is downloaded and cached, otherwise a cached copy is used.
	 *
	 * If the expiration time is not set, then the cache does not expire.
	 *
	 * @param cacheExpirationTimeInMilliseconds long value
	 */
	public void setCacheExpirationTime(final long cacheExpirationTimeInMilliseconds) {
		this.cacheExpirationTime = cacheExpirationTimeInMilliseconds;
	}

	/**
	 * @param cachedSource
	 *            the cachedSource to set
	 */
	public void setProxySource(final OnlineSource<T> cachedSource) {
		this.cachedSource = cachedSource;
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
		final String key = initRevocationTokenKey(certificateToken, issuerCertificateToken);
		final T revocationToken = findRevocation(key, certificateToken, issuerCertificateToken);
		if (revocationToken != null) {
			final Date nextUpdate = revocationToken.getNextUpdate();
			if ((nextUpdate != null) && nextUpdate.after(new Date())) {
				LOG.debug("Revocation token is in cache");
				return revocationToken;
			} else {
				LOG.debug("Revocation token not valid, get new one...");
			}
		}

		if (cachedSource == null) {
			
			LOG.warn("CachedSource is not initialized for the called RevocationSource!");
			return null;
		}
		final T newToken = cachedSource.getRevocationToken(certificateToken, issuerCertificateToken);
		if ((newToken != null) && newToken.isValid()) {
			newToken.initInfo();
			if (revocationToken == null) {
				LOG.info("RevocationToken '{}' is not in cache", newToken);
				insertRevocation(key, newToken);
			} else {
				updateRevocation(key, newToken);
			}
		}
		return newToken;
	}

}
