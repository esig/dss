package eu.europa.esig.dss.tsl.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.result.ValidationResult;

/**
 * This class stores validation information for processed files
 *
 */
public class ValidationCache extends AbstractCache<ValidationResult> {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationCache.class);
	
	/**
	 * Returns the result of signature validation process for a file with the given {@code cacheKey}
	 * @param cacheKey {@link String} key of a file to get signature validation result for
	 * @return TRUE if the signature validation result is valid, FALSE otherwise
	 */
	public boolean isSignatureValid(String cacheKey) {
		LOG.trace("Extracting the validation result for the cache key [{}]...", cacheKey);
		ValidationResult validationResult = getCachedResult(cacheKey);
		if (validationResult != null) {
			boolean isSignatureValid = validationResult.isSignatureValid();
			LOG.trace("Is the signature for a cached file with key [{}] valid? : {}", cacheKey, isSignatureValid);
			return isSignatureValid;
		}
		// the validation is not performed
		LOG.trace("Validation has not beed performed for the cache key [{}]...", cacheKey);
		return false;
	}

}
