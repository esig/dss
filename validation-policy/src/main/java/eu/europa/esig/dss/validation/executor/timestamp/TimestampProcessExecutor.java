package eu.europa.esig.dss.validation.executor.timestamp;

import eu.europa.esig.dss.validation.executor.ProcessExecutor;
import eu.europa.esig.dss.validation.reports.TimestampReports;

public interface TimestampProcessExecutor extends ProcessExecutor<TimestampReports> {
	
	/**
	 * Allows to specify the target timestamp present in the Diagnostic Data to be verified
	 * 
	 * @param timestampId {@link String} id of the timestamp to be verified
	 */
	void setTimestampId(String timestampId);

}
