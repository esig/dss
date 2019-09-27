package eu.europa.esig.dss.tsl.dto;

import java.util.Date;

public class DownloadCacheDTO extends AbstractCacheDTO {

	private static final long serialVersionUID = 514589372769360786L;
	
	private Date lastSynchronizationDate;

	public DownloadCacheDTO() {}
	
	public DownloadCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}
	
	public Date getLastSynchronizationDate() {
		return lastSynchronizationDate;
	}

	public void setLastSynchronizationDate(Date lastSynchronizationDate) {
		this.lastSynchronizationDate = lastSynchronizationDate;
	}
	
	/**
	 * getLastSuccessDate()
	 * @return {@link Date}
	 */
	public Date getLastLoadingDate() {
		return getLastSuccessDate();
	}

}
