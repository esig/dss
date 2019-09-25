package eu.europa.esig.dss.tsl.summary;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;
import eu.europa.esig.dss.tsl.dto.TrustServiceProvider;

/**
 * Computes summary for a single Trusted List processing result
 *
 */
public class TLInfo {
	
	/**
	 * Current TLSource
	 */
	protected final CacheKey cacheKey;
	private final String url;

	protected final DownloadCache downloadCache;
	protected final ParsingCache parsingCache;
	protected final ValidationCache validationCache;
	
	/**
	 * The default constructor
	 * @param downloadCache {@link DownloadCache}
	 * @param parsingCache {@link ParsingCache}
	 * @param validationCache {@link ValidationCache}
	 */
	public TLInfo(final CacheKey cacheKey, final String url, final DownloadCache downloadCache, final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.cacheKey = cacheKey;
		this.url = url;
		this.downloadCache = downloadCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}
	
	/**
	 * Returns the download result state for the current TLSource
	 * @return {@link CacheStateEnum}
	 */
	public CacheStateEnum getDownloadJobState() {
		return downloadCache.getCurrentState(cacheKey);
	}
	
	/**
	 * Returns a cached exception message of a download job for current TL
	 * @return {@link String} exception message
	 */
	public String getDownloadJobExceptionMessage() {
		return downloadCache.getCachedExceptionMessage(cacheKey);
	}
	
	/**
	 * Returns a cached exception stackTrace of a download job for current TL
	 * @return {@link String} exception stack trace
	 */
	public String getDownloadJobExceptionStackTrace() {
		return downloadCache.getCachedExceptionStackTrace(cacheKey);
	}
	
	/**
	 * Returns a URL that was used to download the remote file
	 * @return {@link String} url
	 */
	public String getUrl() {
		return url;
	}
	
	/**
	 * Returns a date of last file loading from a remote source
	 * @return {@link Date} last loading date
	 */
	public Date getLastLoadingDate() {
		return downloadCache.getLastSuccessDate(cacheKey);
	}

	/**
	 * Returns a date of last file synchronization with a remote source
	 * @return {@link Date} last synchronization date
	 */
	public Date getLastFileSynchronizationDate() {
		return downloadCache.getLastSynchronizationDate(cacheKey);
	}
	
	/**
	 * Returns the parsing result state for the current TLSource
	 * @return {@link CacheStateEnum}
	 */
	public CacheStateEnum getParsingJobState() {
		return parsingCache.getCurrentState(cacheKey);
	}
	
	/**
	 * Returns a cached exception message of a parsing job for current TL
	 * @return {@link String} exception message
	 */
	public String getParsingJobExceptionMessage() {
		return parsingCache.getCachedExceptionMessage(cacheKey);
	}
	
	/**
	 * Returns a cached exception stack trace of a parsing job for current TL
	 * @return {@link String} exception stack trace
	 */
	public String getParsingJobExceptionStackTrace() {
		return parsingCache.getCachedExceptionStackTrace(cacheKey);
	}

	/**
	 * Returns a sequence number of a current TL
	 * @return {@link Integer} sequence number
	 */
	public Integer getSequenceNumber() {
		return parsingCache.getSequenceNumber(cacheKey);
	}

	/**
	 * Returns a version of a current TL
	 * @return {@link Integer} version
	 */
	public Integer getTLVersion() {
		return parsingCache.getVersion(cacheKey);
	}

	/**
	 * Returns a territory (country) of a current TL
	 * @return {@link String} territory
	 */
	public String getTerritory() {
		return parsingCache.getTerritory(cacheKey);
	}

	/**
	 * Returns an issue date of a current TL
	 * @return {@link Date} issue date
	 */
	public Date getIssueDate() {
		return parsingCache.getIssueDate(cacheKey);
	}

	/**
	 * Returns a next update date of a current TL
	 * @return {@link Date} next update date
	 */
	public Date getNextUpdateDate() {
		return parsingCache.getNextUpdateDate(cacheKey);
	}

	/**
	 * Returns a list of distribution points for the current TL
	 * @return list of {@link String} distribution points
	 */
	public List<String> getDistributionPoints() {
		return parsingCache.getDistributionPoints(cacheKey);
	}

	/**
	 * Returns a list of TrustServiceProviders for the current TL
	 * @return list of {@link TrustServiceProvider}s
	 */
	public List<TrustServiceProvider> getTrustServiceProviders() {
		return parsingCache.getTrustServiceProviders(cacheKey);
	}
	
	/**
	 * Returns the validation result state for the current TLSource
	 * @return {@link CacheStateEnum}
	 */
	public CacheStateEnum getValidationJobState() {
		return validationCache.getCurrentState(cacheKey);
	}
	
	/**
	 * Returns a cached exception message of a validation job for current TL
	 * @return {@link String} exception message
	 */
	public String getValidationJobExceptionMessage() {
		return validationCache.getCachedExceptionMessage(cacheKey);
	}
	
	/**
	 * Returns a cached exception stack trace of a validation job for current TL
	 * @return {@link String} exception stack trace
	 */
	public String getValidationJobExceptionStackTrace() {
		return validationCache.getCachedExceptionStackTrace(cacheKey);
	}
	
	/**
	 * Returns validation result Indication for the current TL
	 * @return {@link Indication} of validation
	 */
	public Indication getValidationIndication() {
		return validationCache.getIndication(cacheKey);
	}
	
	/**
	 * Returns validation result SubIndication for the current TL
	 * @return {@link SubIndication} of validation
	 */
	public SubIndication getValidationSubIndication() {
		return validationCache.getSubIndication(cacheKey);
	}
	
	/**
	 * Returns a signing time of a current TL
	 * @return {@link Date} signing time
	 */
	public Date getTLSigningTime() {
		return validationCache.getSigningTime(cacheKey);
	}
	
	/**
	 * Returns a signing certificate of a current TL
	 * @return {@link CertificateToken} signing certificate
	 */
	public CertificateToken getTLSigningCertificate() {
		return validationCache.getSigningCertificate(cacheKey);
	}

}
