package eu.europa.esig.dss.model;

/**
 * This class contains only a binary representation of a timestamp
 *
 */
public class TimestampBinary {
	
	private byte[] binary;
	
	public TimestampBinary(byte[] binary) {
		this.binary = binary;
	}
	
	public byte[] getEncoded() {
		return binary;
	}

}
