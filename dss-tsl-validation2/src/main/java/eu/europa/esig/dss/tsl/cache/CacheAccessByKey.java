package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.tsl.download.XmlDownloadResult;
import eu.europa.esig.dss.tsl.parsing.TLParsingResult;
import eu.europa.esig.dss.tsl.validation.ValidationResult;

public class CacheAccessByKey {

	/* Key of the CacheEntry */
	private final CacheKey key;

	/* Global Cache */
	private final DownloadCache fileCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;
	
	public CacheAccessByKey(final CacheKey key, final DownloadCache fileCache, final ParsingCache parsingCache,
			final ValidationCache validationCache) {
		this.key = key;
		this.fileCache = fileCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
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

	public void update(TLParsingResult tlParsingResult) {
		parsingCache.update(key, tlParsingResult);
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

}
