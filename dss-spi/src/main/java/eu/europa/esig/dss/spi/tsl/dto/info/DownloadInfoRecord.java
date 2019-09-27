package eu.europa.esig.dss.spi.tsl.dto.info;

import java.util.Date;

public interface DownloadInfoRecord extends InfoRecord {
	
	public Date getLastSynchronizationDate();
	
	public Date getLastLoadingDate();

}
