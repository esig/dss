package eu.europa.esig.dss.tsl.cache.access;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;
import eu.europa.esig.dss.tsl.dto.DownloadCacheDTO;
import eu.europa.esig.dss.tsl.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.dto.ValidationCacheDTO;
import eu.europa.esig.dss.tsl.dto.builder.DownloadCacheDTOBuilder;
import eu.europa.esig.dss.tsl.dto.builder.ParsingCacheDTOBuilder;
import eu.europa.esig.dss.tsl.dto.builder.ValidationCacheDTOBuilder;

public class ReadOnlyCacheAccess {

	private static final Logger LOG = LoggerFactory.getLogger(ReadOnlyCacheAccess.class);

	/* Global Cache */
	protected final DownloadCache downloadCache;
	protected final ParsingCache parsingCache;
	protected final ValidationCache validationCache;

	public ReadOnlyCacheAccess(final DownloadCache fileCache, final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.downloadCache = fileCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}

	/**
	 * Returns download cache DTO result
	 * 
	 * @param key {@link CacheKey} to extract download result for
	 * @return {@link DownloadCacheDTO}
	 */
	public DownloadCacheDTO getDownloadCacheDTO(final CacheKey key) {
		LOG.trace("Extracting a download cache for an entry with the key [{}]", key);
		return new DownloadCacheDTOBuilder(downloadCache.get(key)).build();
	}

	/**
	 * Returns download cache DTO result
	 * 
	 * @param key {@link CacheKey} to extract download result for
	 * @return {@link DownloadCacheDTO}
	 */
	public ParsingCacheDTO getParsingCacheDTO(final CacheKey key) {
		LOG.trace("Extracting a parsing cache for an entry with the key [{}]", key);
		return new ParsingCacheDTOBuilder(parsingCache.get(key)).build();
	}

	/**
	 * Returns download cache DTO result
	 * 
	 * @param key {@link CacheKey} to extract download result for
	 * @return {@link DownloadCacheDTO}
	 */
	public ValidationCacheDTO getValidationCacheDTO(final CacheKey key) {
		LOG.trace("Extracting a validation cache for an entry with the key [{}]", key);
		return new ValidationCacheDTOBuilder(validationCache.get(key)).build();
	}

}
