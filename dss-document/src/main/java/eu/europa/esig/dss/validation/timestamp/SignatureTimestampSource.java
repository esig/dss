package eu.europa.esig.dss.validation.timestamp;

import java.util.List;

public interface SignatureTimestampSource {
	
	List<TimestampToken> getContentTimestamps();
	
	List<TimestampToken> getSignatureTimestamps();
	
	List<TimestampToken> getTimestampsX1();
	
	List<TimestampToken> getTimestampsX2();
	
	List<TimestampToken> getArchiveTimestamps();
	
	List<TimestampToken> getDocumentTimestamps();
	
	/**
	 * This method allows to add an external timestamp. The given timestamp must be processed before.
	 * 
	 * @param timestamp
	 *            the timestamp token
	 */
	void addExternalTimestamp(TimestampToken timestamp);

}
