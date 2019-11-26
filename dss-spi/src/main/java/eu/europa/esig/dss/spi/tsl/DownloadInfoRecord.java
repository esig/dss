package eu.europa.esig.dss.spi.tsl;

import java.util.Date;

public interface DownloadInfoRecord extends InfoRecord {
	
	Date getLastSynchronizationDate();
	
	Date getLastLoadingDate();

}
