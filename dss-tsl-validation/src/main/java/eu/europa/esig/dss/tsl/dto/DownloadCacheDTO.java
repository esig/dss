package eu.europa.esig.dss.tsl.dto;

import java.util.Date;

import eu.europa.esig.dss.spi.tsl.DownloadInfoRecord;

public class DownloadCacheDTO extends AbstractCacheDTO implements DownloadInfoRecord {

	private static final long serialVersionUID = 514589372769360786L;
	
	private Date lastSuccessDownloadTime;

	public DownloadCacheDTO() {}
	
	public DownloadCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}
	
	@Override
	public Date getLastSuccessDownloadTime() {
		return lastSuccessDownloadTime;
	}

	public void setLastSuccessDownloadTime(Date lastSuccessDownloadTime) {
		this.lastSuccessDownloadTime = lastSuccessDownloadTime;
	}

	@Override
	public Date getLastDownloadAttemptTime() {
		return latestDate(latestDate(lastSuccessDownloadTime, getLastStateTransitionTime()), getExceptionLastOccurrenceTime());
	}

	/**
	 * Compare two dates
	 * @return the latest of the two dates
	 */
	public static Date latestDate(Date a, Date b) {
	    return a == null ? b : (b == null ? a : (a.after(b) ? a : b));
	}
}
