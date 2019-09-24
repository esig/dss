package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.parsing.AbstractParsingResult;
import eu.europa.esig.dss.tsl.validation.ValidationResult;

public class ReadOnlyCacheAccess {

	/* Global Cache */
	private final DownloadCache fileCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;

	public ReadOnlyCacheAccess(final DownloadCache fileCache, final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.fileCache = fileCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}

	public XmlDownloadResult getDownloadResult(CacheKey key) {
		return fileCache.get(key).getCachedResult();
	}

	public AbstractParsingResult getParsingResult(CacheKey key) {
		return parsingCache.get(key).getCachedResult();
	}

	public ValidationResult getValidationResult(CacheKey key) {
		return validationCache.get(key).getCachedResult();
	}

}
