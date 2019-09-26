package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.tsl.validation.ValidationResult;

/**
 * This class stores validation information for processed files
 *
 */
public class ValidationCache extends AbstractCache<ValidationResult> {

	@Override
	protected CacheType getCacheType() {
		return CacheType.VALIDATION;
	}

}
