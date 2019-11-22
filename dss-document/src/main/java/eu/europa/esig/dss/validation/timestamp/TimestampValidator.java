package eu.europa.esig.dss.validation.timestamp;

import java.util.List;

public interface TimestampValidator {
	
	/**
	 * Returns a list of detached timestamps
	 * 
	 * @return a list of {@link TimestampToken}s
	 */
	List<TimestampToken> getTimestamps();

}
