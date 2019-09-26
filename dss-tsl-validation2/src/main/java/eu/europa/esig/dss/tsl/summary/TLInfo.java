package eu.europa.esig.dss.tsl.summary;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;
import eu.europa.esig.dss.tsl.dto.TrustServiceProvider;

/**
 * Computes summary for a single Trusted List processing result
 *
 */
public class TLInfo {
	
	/**
	 * Current cache access by key
	 */
	protected final CacheAccessByKey cacheAccessByKey;

	/**
	 * Address of the source
	 */
	private final String url;
	
	/**
	 * The default constructor
	 * @param cacheAccessByKey {@link CacheAccessByKey} a related cache access object
	 * @param url {@link String} address used to extract the entry
	 */
	public TLInfo(final CacheAccessByKey cacheAccessByKey, final String url) {
		this.cacheAccessByKey = cacheAccessByKey;
		this.url = url;
	}
	
	/**
	 * Returns the download result state for the current TLSource
	 * @return {@link CacheStateEnum}
	 */
	public CacheStateEnum getDownloadJobState() {
		return cacheAccessByKey.getDownloadCacheDataAccess().getCurrentState();
	}
	
	/**
	 * Returns a cached exception message of a download job for current TL
	 * @return {@link String} exception message
	 */
	public String getDownloadJobExceptionMessage() {
		return cacheAccessByKey.getDownloadCacheDataAccess().getCachedExceptionMessage();
	}
	
	/**
	 * Returns a cached exception stackTrace of a download job for current TL
	 * @return {@link String} exception stack trace
	 */
	public String getDownloadJobExceptionStackTrace() {
		return cacheAccessByKey.getDownloadCacheDataAccess().getCachedExceptionStackTrace();
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
		return cacheAccessByKey.getDownloadCacheDataAccess().getLastSuccessDate();
	}

	/**
	 * Returns a date of last file synchronization with a remote source
	 * @return {@link Date} last synchronization date
	 */
	public Date getLastFileSynchronizationDate() {
		return cacheAccessByKey.getDownloadCacheDataAccess().getLastSynchronizationDate();
	}
	
	/**
	 * Returns the parsing result state for the current TLSource
	 * @return {@link CacheStateEnum}
	 */
	public CacheStateEnum getParsingJobState() {
		return cacheAccessByKey.getParsingCacheDataAccess().getCurrentState();
	}
	
	/**
	 * Returns a cached exception message of a parsing job for current TL
	 * @return {@link String} exception message
	 */
	public String getParsingJobExceptionMessage() {
		return cacheAccessByKey.getParsingCacheDataAccess().getCachedExceptionMessage();
	}
	
	/**
	 * Returns a cached exception stack trace of a parsing job for current TL
	 * @return {@link String} exception stack trace
	 */
	public String getParsingJobExceptionStackTrace() {
		return cacheAccessByKey.getParsingCacheDataAccess().getCachedExceptionStackTrace();
	}

	/**
	 * Returns a sequence number of a current TL
	 * @return {@link Integer} sequence number
	 */
	public Integer getSequenceNumber() {
		return cacheAccessByKey.getParsingCacheDataAccess().getSequenceNumber();
	}

	/**
	 * Returns a version of a current TL
	 * @return {@link Integer} version
	 */
	public Integer getTLVersion() {
		return cacheAccessByKey.getParsingCacheDataAccess().getVersion();
	}

	/**
	 * Returns a territory (country) of a current TL
	 * @return {@link String} territory
	 */
	public String getTerritory() {
		return cacheAccessByKey.getParsingCacheDataAccess().getTerritory();
	}

	/**
	 * Returns an issue date of a current TL
	 * @return {@link Date} issue date
	 */
	public Date getIssueDate() {
		return cacheAccessByKey.getParsingCacheDataAccess().getIssueDate();
	}

	/**
	 * Returns a next update date of a current TL
	 * @return {@link Date} next update date
	 */
	public Date getNextUpdateDate() {
		return cacheAccessByKey.getParsingCacheDataAccess().getNextUpdateDate();
	}

	/**
	 * Returns a list of distribution points for the current TL
	 * @return list of {@link String} distribution points
	 */
	public List<String> getDistributionPoints() {
		return cacheAccessByKey.getParsingCacheDataAccess().getDistributionPoints();
	}

	/**
	 * Returns a list of TrustServiceProviders for the current TL
	 * @return list of {@link TrustServiceProvider}s
	 */
	public List<TrustServiceProvider> getTrustServiceProviders() {
		return cacheAccessByKey.getParsingCacheDataAccess().getTrustServiceProviders();
	}
	
	/**
	 * Returns the validation result state for the current TLSource
	 * @return {@link CacheStateEnum}
	 */
	public CacheStateEnum getValidationJobState() {
		return cacheAccessByKey.getValidationCacheDataAccess().getCurrentState();
	}
	
	/**
	 * Returns a cached exception message of a validation job for current TL
	 * @return {@link String} exception message
	 */
	public String getValidationJobExceptionMessage() {
		return cacheAccessByKey.getValidationCacheDataAccess().getCachedExceptionMessage();
	}
	
	/**
	 * Returns a cached exception stack trace of a validation job for current TL
	 * @return {@link String} exception stack trace
	 */
	public String getValidationJobExceptionStackTrace() {
		return cacheAccessByKey.getValidationCacheDataAccess().getCachedExceptionStackTrace();
	}
	
	/**
	 * Returns validation result Indication for the current TL
	 * @return {@link Indication} of validation
	 */
	public Indication getValidationIndication() {
		return cacheAccessByKey.getValidationCacheDataAccess().getIndication();
	}
	
	/**
	 * Returns validation result SubIndication for the current TL
	 * @return {@link SubIndication} of validation
	 */
	public SubIndication getValidationSubIndication() {
		return cacheAccessByKey.getValidationCacheDataAccess().getSubIndication();
	}
	
	/**
	 * Returns a signing time of a current TL
	 * @return {@link Date} signing time
	 */
	public Date getTLSigningTime() {
		return cacheAccessByKey.getValidationCacheDataAccess().getSigningTime();
	}
	
	/**
	 * Returns a signing certificate of a current TL
	 * @return {@link CertificateToken} signing certificate
	 */
	public CertificateToken getTLSigningCertificate() {
		return cacheAccessByKey.getValidationCacheDataAccess().getSigningCertificate();
	}

}
