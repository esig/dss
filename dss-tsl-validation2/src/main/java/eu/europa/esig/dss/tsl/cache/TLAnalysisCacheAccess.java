package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.tsl.download.XmlDownloadResult;

public class TLAnalysisCacheAccess {

	private final String key;

	private FileCache fileCache;
	private ExtractionCache parsingCache;
	private ValidationCache validationCache;

	public XmlDownloadResult getCachedDownloadResult() {
		return fileCache.getCachedResult(key);
	}

	public boolean isParsingRefreshNeeded() {
		return parsingCache.isRefreshNeeded(key);
	}

	public boolean isValidationRefreshNeeded() {
		return validationCache.isRefreshNeeded(key);
	}

	public void expireParsing() {
		parsingCache.expire(key);
	}

	public void expireValidation() {
		validationCache.expire(key);
	}

}
