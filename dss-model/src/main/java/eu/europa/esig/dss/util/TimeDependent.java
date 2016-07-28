package eu.europa.esig.dss.util;

import java.util.Date;

/**
 * Valid in a specific time interval.
 * @author jdvorak
 */
public interface TimeDependent {
	
	/**
	 * The start of the validity period. 
	 * It shall never be null.
	 */
	Date getStartDate();

	/**
	 * The end of the validity period.
	 * Null indicates that this is the last known case.
	 * If not null, it is assumed that the end date is not older than the start date.
	 */
	Date getEndDate();

}
