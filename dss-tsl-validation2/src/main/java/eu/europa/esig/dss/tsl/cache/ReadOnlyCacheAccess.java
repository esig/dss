package eu.europa.esig.dss.tsl.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.dto.DownloadCacheDTO;
import eu.europa.esig.dss.tsl.cache.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.cache.dto.ValidationCacheDTO;

public class ReadOnlyCacheAccess {

	private static final Logger LOG = LoggerFactory.getLogger(ReadOnlyCacheAccess.class);

	/* Global Cache */
	private final DownloadCache fileCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;

	public ReadOnlyCacheAccess(final DownloadCache fileCache, final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.fileCache = fileCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}
	
	/**
	 * Returns download cache DTO result
	 * @param key {@link CacheKey} to extract download result for
	 * @return {@link DownloadCacheDTO}
	 */
	public DownloadCacheDTO getDownloadCacheDTO(final CacheKey key) {
		LOG.trace("Extracting a download cache for an entry with the key [{}]", key);
		return new DownloadCacheDTOBuilder(fileCache.get(key)).build();
	}
	
	/**
	 * Returns download cache DTO result
	 * @param key {@link CacheKey} to extract download result for
	 * @return {@link DownloadCacheDTO}
	 */
	public ParsingCacheDTO getParsingCacheDTO(final CacheKey key) {
		LOG.trace("Extracting a parsing cache for an entry with the key [{}]", key);
		return new ParsingCacheDTOBuilder(parsingCache.get(key)).build();
	}
	
//	public Map<CacheKey, AbstractParsingResult> getParsingResultMap(List<CacheKey> keys) {
//		return keys.stream().collect(Collectors.toMap(key -> key, key -> getParsingResult(key)));
//	}
	
	/**
	 * Returns download cache DTO result
	 * @param key {@link CacheKey} to extract download result for
	 * @return {@link DownloadCacheDTO}
	 */
	public ValidationCacheDTO getValidationCacheDTO(final CacheKey key) {
		LOG.trace("Extracting a validation cache for an entry with the key [{}]", key);
		return new ValidationCacheDTOBuilder(validationCache.get(key)).build();
	}

}
