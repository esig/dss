package eu.europa.esig.dss.model;

/**
 * This class contains only a binary representation of a timestamp
 *
 */
public class TimestampBinary {
	
	private final byte[] binary;
	
	public TimestampBinary(final byte[] binary) {
		this.binary = binary;
	}
	
	public byte[] getEncoded() {
		return binary;
	}

}
