package eu.europa.esig.dss.model;

/**
 * This class contains only a binary representation of a timestamp
 *
 */
public class TimestampBinary {
	
	private final byte[] bytes;
	
	public TimestampBinary(final byte[] bytes) {
		this.bytes = bytes;
	}
	
	public byte[] getBytes() {
		return bytes;
	}

}
