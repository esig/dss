package eu.europa.esig.dss.tsl.summary;

import java.io.Serializable;

import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.cache.dto.DownloadCacheDTO;
import eu.europa.esig.dss.tsl.cache.dto.ParsingCacheDTO;
import eu.europa.esig.dss.tsl.cache.dto.ValidationCacheDTO;

/**
 * Computes summary for a single Trusted List processing result
 *
 */
public class TLInfo implements Serializable {
	
	private static final long serialVersionUID = -1505115221927652721L;

	/**
	 * Address of the source
	 */
	private final String url;
	
	/* DTOs */
	private DownloadCacheDTO downloadCacheInfo;
	private ParsingCacheDTO parsingCacheInfo;
	private ValidationCacheDTO validationCacheInfo;
	
	/**
	 * The default constructor
	 * @param cacheAccessByKey {@link CacheAccessByKey} a related cache access object
	 * @param url {@link String} address used to extract the entry
	 */
	public TLInfo(final CacheAccessByKey cacheAccessByKey, final String url) {
		this.downloadCacheInfo = cacheAccessByKey.getDownloadCacheDataAccess().getCacheDTO();
		this.parsingCacheInfo = cacheAccessByKey.getParsingCacheDataAccess().getCacheDTO();
		this.validationCacheInfo = cacheAccessByKey.getValidationCacheDataAccess().getCacheDTO();
		this.url = url;
	}
	
	/**
	 * Returns Download Cache Info
	 * @return {@link DownloadCacheDTO}
	 */
	public DownloadCacheDTO getDownloadCacheInfo() {
		return downloadCacheInfo;
	}
	
	/**
	 * Returns Parsing Cache Info
	 * @return {@link ParsingCacheDTO}
	 */
	public ParsingCacheDTO getParsingCacheInfo() {
		return parsingCacheInfo;
	}
	
	/**
	 * Returns Validation Cache Info
	 * @return {@link ParsingCacheDTO}
	 */
	public ValidationCacheDTO getValidationCacheInfo() {
		return validationCacheInfo;
	}
	
	/**
	 * Returns a URL that was used to download the remote file
	 * @return {@link String} url
	 */
	public String getUrl() {
		return url;
	}

}
