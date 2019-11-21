package eu.europa.esig.dss.spi.tsl;

import java.io.Serializable;
import java.util.Date;

public interface InfoRecord extends Serializable {
	
	boolean isRefreshNeeded();
	
	boolean isDesynchronized();
	
	boolean isSynchronized();
	
	boolean isError();
	
	boolean isToBeDeleted();
	
	String getStatusName();
	
	Date getLastStateTransitionTime();
	
	String getExceptionMessage();
	
	String getExceptionStackTrace();
	
	Date getExceptionFirstOccurrenceTime();
	
	boolean isResultExist();

}
