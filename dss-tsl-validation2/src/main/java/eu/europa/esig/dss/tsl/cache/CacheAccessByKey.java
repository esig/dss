package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.tsl.cache.dto.DownloadCacheDTO;
import eu.europa.esig.dss.tsl.cache.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.cache.dto.ValidationCacheDTO;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.validation.ValidationResult;

public class CacheAccessByKey {

	/* Key of the CacheEntry */
	private final CacheKey key;

	/* Global Cache */
	private final DownloadCache fileCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;
	
	private ReadOnlyCacheAccess readOnlyCacheAccess;
	
	public CacheAccessByKey(final CacheKey key, final DownloadCache fileCache, final ParsingCache parsingCache,
			final ValidationCache validationCache) {
		this.key = key;
		this.fileCache = fileCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}
	
	/**
	 * Returns the CacheKey
	 * @return {@link CacheKey}
	 */
	public CacheKey getCacheKey() {
		return key;
	}

	public boolean isUpToDate(XmlDownloadResult xmlDownloadResult) {
		return fileCache.isUpToDate(key, xmlDownloadResult);
	} 

	public void update(XmlDownloadResult result) {
		fileCache.update(key, result);
	}

	public void downloadError(Exception e) {
		fileCache.error(key, e);
	}

	public boolean isParsingRefreshNeeded() {
		return parsingCache.isRefreshNeeded(key);
	}

	public void update(AbstractParsingResult parsingResult) {
		parsingCache.update(key, parsingResult);
	}

	public void expireParsing() {
		parsingCache.expire(key);
	}

	public void parsingError(Exception e) {
		parsingCache.error(key, e);
	}

	public boolean isValidationRefreshNeeded() {
		return validationCache.isRefreshNeeded(key);
	}

	public void expireValidation() {
		validationCache.expire(key);
	}

	public void update(ValidationResult validationResult) {
		validationCache.update(key, validationResult);
	}

	public void validationError(Exception e) {
		validationCache.error(key, e);
	}
	
	/**
	 * Checks if the entry must be deleted from the file cache (download cache)
	 * @return TRUE if the entry need to be deleted, FALSE otherwise
	 */
	public boolean isFileNeedToBeDeleted() {
		return fileCache.isToBeDeleted(key);
	}
	
	/**
	 * Removes the entry from downloadCache if its value is TO_BE_DELETED
	 */
	public void deleteDownloadCacheIfNeeded() {
		if (fileCache.isToBeDeleted(key)) {
			fileCache.remove(key);
		}
	}
	
	/**
	 * Removes the entry from parsingCache if its value is TO_BE_DELETED
	 */
	public void deleteParsingCacheIfNeeded() {
		if (parsingCache.isToBeDeleted(key)) {
			parsingCache.remove(key);
		}
	}
	
	/**
	 * Removes the entry from parsingCache if its value is TO_BE_DELETED
	 */
	public void deleteValidationCacheIfNeeded() {
		if (validationCache.isToBeDeleted(key)) {
			validationCache.remove(key);
		}
	}
	
	private ReadOnlyCacheAccess getReadOnlyCacheAccess() {
		if (readOnlyCacheAccess == null) {
			readOnlyCacheAccess = new ReadOnlyCacheAccess(fileCache, parsingCache, validationCache);
		}
		return readOnlyCacheAccess;
	}

	/**
	 * Returns the cached read-only download result DTO
	 * 
	 * @return {@link DownloadCacheDTO}
	 */
	public DownloadCacheDTO getDownloadReadOnlyResult() {
		return getReadOnlyCacheAccess().getDownloadCacheDTO(key);
	}

	/**
	 * Returns the cached read-only parsing result DTO
	 * 
	 * @return {@link ParsingCacheDTO}
	 */
	public ParsingCacheDTO getParsingReadOnlyResult() {
		return getReadOnlyCacheAccess().getParsingCacheDTO(key);
	}

	/**
	 * Returns the cached read-only validation result DTO
	 * 
	 * @return {@link ValidationCacheDTO}
	 */
	public ValidationCacheDTO getValidationReadOnlyResult() {
		return getReadOnlyCacheAccess().getValidationCacheDTO(key);
	}

}
