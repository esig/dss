package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.tsl.dto.DownloadCacheDTO;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.dto.ValidationCacheDTO;

public class ReadOnlyCacheByKey {

	/* Key of the CacheEntry */
	protected final CacheKey key;

	/* Global Cache */
	protected final DownloadCache fileCache;
	protected final ParsingCache parsingCache;
	protected final ValidationCache validationCache;
	
	private final ReadOnlyCacheAccess readOnlyCacheAccess;

	public ReadOnlyCacheByKey(final CacheKey key, final DownloadCache fileCache, 
			final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.key = key;
		this.fileCache = fileCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
		this.readOnlyCacheAccess = new ReadOnlyCacheAccess(fileCache, parsingCache, validationCache);
	}

	/**
	 * Returns the cached read-only download result DTO
	 * 
	 * @return {@link DownloadCacheDTO}
	 */
	public DownloadCacheDTO getDownloadReadOnlyResult() {
		return readOnlyCacheAccess.getDownloadCacheDTO(key);
	}

	/**
	 * Returns the cached read-only parsing result DTO
	 * 
	 * @return {@link ParsingCacheDTO}
	 */
	public ParsingCacheDTO getParsingReadOnlyResult() {
		return readOnlyCacheAccess.getParsingCacheDTO(key);
	}

	/**
	 * Returns the cached read-only validation result DTO
	 * 
	 * @return {@link ValidationCacheDTO}
	 */
	public ValidationCacheDTO getValidationReadOnlyResult() {
		return readOnlyCacheAccess.getValidationCacheDTO(key);
	}

}
