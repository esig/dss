package eu.europa.esig.dss.tsl.cache;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.validation.ValidationResult;

/**
 * This class stores validation information for processed files
 *
 */
public class ValidationCache extends AbstractCache<ValidationResult> {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationCache.class);
	
	/**
	 * Returns the validation main indication for an entry with the given key
	 * @param cacheKey {@link CacheKey} of the cached entry to get validation Indication
	 * @return {@link Indication} validation main indication
	 */
	public Indication getIndication(CacheKey cacheKey) {
		LOG.trace("Extracting the validation main indication for the key [{}]...", cacheKey);
		CachedEntry<ValidationResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			ValidationResult cachedResult = cachedEntry.getCachedResult();
			Indication indication = cachedResult.getIndication();
			LOG.trace("The validation indication for a file with the key [{}] is [{}]", cacheKey, indication.name());
			return indication;
		}
		LOG.debug("The ValidationCache does not contain a validation result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns the validation subIndication for an entry with the given key
	 * @param cacheKey {@link CacheKey} of the cached entry to get validation SubIndication
	 * @return {@link SubIndication} of the validation
	 */
	public SubIndication getSubIndication(CacheKey cacheKey) {
		LOG.trace("Extracting the validation sub indication for the key [{}]...", cacheKey);
		CachedEntry<ValidationResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			ValidationResult cachedResult = cachedEntry.getCachedResult();
			SubIndication subIndication = cachedResult.getSubIndication();
			if (subIndication != null) {
				LOG.trace("The validation subIndication for a file with the key [{}] is [{}]", cacheKey, subIndication.name());
			} else {
				LOG.trace("The validation subIndication for a file with the key [{}] is null", cacheKey);
			}
			return subIndication;
		}
		LOG.debug("The ValidationCache does not contain a validation result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns the signing time of the file with the given {@code cacheKey}
	 * @param cacheKey {@link CacheKey} of the cached entry to get signing time
	 * @return {@link Date} signing time
	 */
	public Date getSigningTime(CacheKey cacheKey) {
		LOG.trace("Extracting the signing time of a file entry with the key [{}]...", cacheKey);
		CachedEntry<ValidationResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			ValidationResult cachedResult = cachedEntry.getCachedResult();
			Date signingTime = cachedResult.getSigningTime();
			LOG.trace("The signing time for a file with the key [{}] is [{}]", cacheKey, signingTime);
			return signingTime;
		}
		LOG.debug("The ValidationCache does not contain a validation result for the key [{}]!", cacheKey);
		return null;
	}
	
	/**
	 * Returns the signing certificate of the file with the given {@code cacheKey}
	 * @param cacheKey {@link CacheKey} of the cached entry to get signing certificate
	 * @return {@link CertificateToken} signing certificate
	 */
	public CertificateToken getSigningCertificate(CacheKey cacheKey) {
		LOG.trace("Extracting the signing certificate of a file entry with the key [{}]...", cacheKey);
		CachedEntry<ValidationResult> cachedEntry = get(cacheKey);
		if (!cachedEntry.isEmpty()) {
			ValidationResult cachedResult = cachedEntry.getCachedResult();
			CertificateToken certificateToken = cachedResult.getSigningCertificate();
			LOG.trace("The signing certificate for a file with the key [{}] is [{}]", cacheKey, certificateToken.getDSSIdAsString());
			return certificateToken;
		}
		LOG.debug("The ValidationCache does not contain a validation result for the key [{}]!", cacheKey);
		return null;
	}

	@Override
	protected CacheType getCacheType() {
		return CacheType.VALIDATION;
	}

}
