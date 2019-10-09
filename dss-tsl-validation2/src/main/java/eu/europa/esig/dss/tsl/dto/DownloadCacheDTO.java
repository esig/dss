package eu.europa.esig.dss.tsl.dto;

import java.util.Date;

import eu.europa.esig.dss.spi.tsl.DownloadInfoRecord;

public class DownloadCacheDTO extends AbstractCacheDTO implements DownloadInfoRecord {

	private static final long serialVersionUID = 514589372769360786L;
	
	private Date lastSynchronizationDate;

	public DownloadCacheDTO() {}
	
	public DownloadCacheDTO(AbstractCacheDTO cacheDTO) {
		super(cacheDTO);
	}
	
	@Override
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
	@Override
	public Date getLastLoadingDate() {
		return getLastSuccessDate();
	}

}
