package eu.europa.esig.dss.tsl.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.validation.AbstractValidationResult;

/**
 * This class stores validation information for processed files
 *
 */
public class ValidationCache extends AbstractCache<AbstractValidationResult> {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationCache.class);
	
	/**
	 * Returns the result of signature validation process for a file with the given {@code cacheKey}
	 * @param cacheKey {@link CacheKey} of a file to get signature validation result for
	 * @return TRUE if the signature validation result is valid, FALSE otherwise
	 */
	public boolean isSignatureValid(CacheKey cacheKey) {
		LOG.trace("Extracting the validation result for the cache key [{}]...", cacheKey);
		CachedEntry<AbstractValidationResult> validationResultEntry = get(cacheKey);
		if (validationResultEntry != null) {
			AbstractValidationResult validationResult = validationResultEntry.getCachedObject();
			boolean isSignatureValid = validationResult.isValid();
			LOG.trace("Is the signature for a cached file with key [{}] valid? : {}", cacheKey, isSignatureValid);
			return isSignatureValid;
		}
		// the validation is not performed
		LOG.trace("Validation has not beed performed for the cache key [{}]...", cacheKey);
		return false;
	}

	@Override
	protected CacheType getCacheType() {
		return CacheType.VALIDATION;
	}

}
