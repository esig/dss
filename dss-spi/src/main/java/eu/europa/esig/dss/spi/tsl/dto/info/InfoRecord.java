package eu.europa.esig.dss.spi.tsl.dto.info;

import java.io.Serializable;
import java.util.Date;

public interface InfoRecord extends Serializable {
	
	public boolean isRefreshNeeded();
	
	public boolean isDesynchronized();
	
	public boolean isSynchronized();
	
	public boolean isError();
	
	public boolean isToBeDeleted();
	
	public Date getLastSuccessDate();
	
	public String getExceptionMessage();
	
	public String getExceptionStackTrace();
	
	public boolean isResultExist();

}
