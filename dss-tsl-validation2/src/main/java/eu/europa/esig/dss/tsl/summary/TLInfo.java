package eu.europa.esig.dss.tsl.summary;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.cache.CacheAccessFactory;
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
	
	/**
	 * The default constructor
	 * @param downloadCache {@link DownloadCache}
	 * @param parsingCache {@link ParsingCache}
	 * @param validationCache {@link ValidationCache}
	 */
	public TLInfo(final CacheKey cacheKey, final String url) {
		this.cacheKey = cacheKey;
		this.url = url;
	}
	
	/**
	 * Returns the download result state for the current TLSource
	 * @return {@link CacheStateEnum}
	 */
	public CacheStateEnum getDownloadJobState() {
		return CacheAccessFactory.getDownloadCacheDataAccess().getCurrentState(cacheKey);
	}
	
	/**
	 * Returns a cached exception message of a download job for current TL
	 * @return {@link String} exception message
	 */
	public String getDownloadJobExceptionMessage() {
		return CacheAccessFactory.getDownloadCacheDataAccess().getCachedExceptionMessage(cacheKey);
	}
	
	/**
	 * Returns a cached exception stackTrace of a download job for current TL
	 * @return {@link String} exception stack trace
	 */
	public String getDownloadJobExceptionStackTrace() {
		return CacheAccessFactory.getDownloadCacheDataAccess().getCachedExceptionStackTrace(cacheKey);
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
		return CacheAccessFactory.getDownloadCacheDataAccess().getLastSuccessDate(cacheKey);
	}

	/**
	 * Returns a date of last file synchronization with a remote source
	 * @return {@link Date} last synchronization date
	 */
	public Date getLastFileSynchronizationDate() {
		return CacheAccessFactory.getDownloadCacheDataAccess().getLastSynchronizationDate(cacheKey);
	}
	
	/**
	 * Returns the parsing result state for the current TLSource
	 * @return {@link CacheStateEnum}
	 */
	public CacheStateEnum getParsingJobState() {
		return CacheAccessFactory.getParsingCacheDataAccess().getCurrentState(cacheKey);
	}
	
	/**
	 * Returns a cached exception message of a parsing job for current TL
	 * @return {@link String} exception message
	 */
	public String getParsingJobExceptionMessage() {
		return CacheAccessFactory.getParsingCacheDataAccess().getCachedExceptionMessage(cacheKey);
	}
	
	/**
	 * Returns a cached exception stack trace of a parsing job for current TL
	 * @return {@link String} exception stack trace
	 */
	public String getParsingJobExceptionStackTrace() {
		return CacheAccessFactory.getParsingCacheDataAccess().getCachedExceptionStackTrace(cacheKey);
	}

	/**
	 * Returns a sequence number of a current TL
	 * @return {@link Integer} sequence number
	 */
	public Integer getSequenceNumber() {
		return CacheAccessFactory.getParsingCacheDataAccess().getSequenceNumber(cacheKey);
	}

	/**
	 * Returns a version of a current TL
	 * @return {@link Integer} version
	 */
	public Integer getTLVersion() {
		return CacheAccessFactory.getParsingCacheDataAccess().getVersion(cacheKey);
	}

	/**
	 * Returns a territory (country) of a current TL
	 * @return {@link String} territory
	 */
	public String getTerritory() {
		return CacheAccessFactory.getParsingCacheDataAccess().getTerritory(cacheKey);
	}

	/**
	 * Returns an issue date of a current TL
	 * @return {@link Date} issue date
	 */
	public Date getIssueDate() {
		return CacheAccessFactory.getParsingCacheDataAccess().getIssueDate(cacheKey);
	}

	/**
	 * Returns a next update date of a current TL
	 * @return {@link Date} next update date
	 */
	public Date getNextUpdateDate() {
		return CacheAccessFactory.getParsingCacheDataAccess().getNextUpdateDate(cacheKey);
	}

	/**
	 * Returns a list of distribution points for the current TL
	 * @return list of {@link String} distribution points
	 */
	public List<String> getDistributionPoints() {
		return CacheAccessFactory.getParsingCacheDataAccess().getDistributionPoints(cacheKey);
	}

	/**
	 * Returns a list of TrustServiceProviders for the current TL
	 * @return list of {@link TrustServiceProvider}s
	 */
	public List<TrustServiceProvider> getTrustServiceProviders() {
		return CacheAccessFactory.getParsingCacheDataAccess().getTrustServiceProviders(cacheKey);
	}
	
	/**
	 * Returns the validation result state for the current TLSource
	 * @return {@link CacheStateEnum}
	 */
	public CacheStateEnum getValidationJobState() {
		return CacheAccessFactory.getValidationCacheDataAccess().getCurrentState(cacheKey);
	}
	
	/**
	 * Returns a cached exception message of a validation job for current TL
	 * @return {@link String} exception message
	 */
	public String getValidationJobExceptionMessage() {
		return CacheAccessFactory.getValidationCacheDataAccess().getCachedExceptionMessage(cacheKey);
	}
	
	/**
	 * Returns a cached exception stack trace of a validation job for current TL
	 * @return {@link String} exception stack trace
	 */
	public String getValidationJobExceptionStackTrace() {
		return CacheAccessFactory.getValidationCacheDataAccess().getCachedExceptionStackTrace(cacheKey);
	}
	
	/**
	 * Returns validation result Indication for the current TL
	 * @return {@link Indication} of validation
	 */
	public Indication getValidationIndication() {
		return CacheAccessFactory.getValidationCacheDataAccess().getIndication(cacheKey);
	}
	
	/**
	 * Returns validation result SubIndication for the current TL
	 * @return {@link SubIndication} of validation
	 */
	public SubIndication getValidationSubIndication() {
		return CacheAccessFactory.getValidationCacheDataAccess().getSubIndication(cacheKey);
	}
	
	/**
	 * Returns a signing time of a current TL
	 * @return {@link Date} signing time
	 */
	public Date getTLSigningTime() {
		return CacheAccessFactory.getValidationCacheDataAccess().getSigningTime(cacheKey);
	}
	
	/**
	 * Returns a signing certificate of a current TL
	 * @return {@link CertificateToken} signing certificate
	 */
	public CertificateToken getTLSigningCertificate() {
		return CacheAccessFactory.getValidationCacheDataAccess().getSigningCertificate(cacheKey);
	}

}
