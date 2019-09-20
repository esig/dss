package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.download.XmlDownloadResult;

public class TLAnalysisCacheAccess {

	/* Key of the CacheEntry */
	private final CacheKey key;

	/* Global Cache */
	private final DownloadCache fileCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;
	
	public TLAnalysisCacheAccess(final CacheKey key, final DownloadCache fileCache, final ParsingCache parsingCache,
			final ValidationCache validationCache) {
		this.key = key;
		this.fileCache = fileCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}

	public CachedEntry<XmlDownloadResult> getCachedDownloadResult() {
		return fileCache.get(key);
	}
	
	public boolean isUpToDate(XmlDownloadResult xmlDownloadResult) {
		return fileCache.isUpToDate(key, xmlDownloadResult);
	} 

	public boolean isParsingRefreshNeeded() {
		return parsingCache.isRefreshNeeded(key);
	}

	public boolean isValidationRefreshNeeded() {
		return validationCache.isRefreshNeeded(key);
	}

	public void expireParsing() {
		parsingCache.isRefreshNeeded(key);
	}

	public void expireValidation() {
		validationCache.isRefreshNeeded(key);
	}

}
