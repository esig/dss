package eu.europa.esig.dss.validation.timestamp;

import java.util.List;

import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.executor.timestamp.TimestampProcessExecutor;

public interface TimestampValidator extends DocumentValidator {
	
	/**
	 * Returns a list of detached timestamps
	 * 
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getTimestamps();
	
	/**
	 * Returns a default implementation of a process executor for timestamp validation
	 * 
	 * @return {@link TimestampProcessExecutor}
	 */
	TimestampProcessExecutor getDefaultProcessExecutor();

}
