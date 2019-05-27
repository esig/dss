package eu.europa.esig.dss.validation.timestamp;

import java.util.List;

public interface SignatureTimestampSource {
	
	List<TimestampToken> getContentTimestamps();
	
	List<TimestampToken> getSignatureTimestamps();
	
	List<TimestampToken> getTimestampsX1();
	
	List<TimestampToken> getTimestampsX2();
	
	List<TimestampToken> getArchiveTimestamps();

}
