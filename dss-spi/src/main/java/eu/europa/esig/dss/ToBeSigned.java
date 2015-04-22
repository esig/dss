package eu.europa.esig.dss;

/**
 * Data unit for signing
 */
public class ToBeSigned {

	private byte[] bytes;

	public ToBeSigned() {
	}

	public ToBeSigned(byte[] bytes) {
		this.bytes = bytes;
	}

	public byte[] getBytes() {
		return bytes;
	}

	public void setBytes(byte[] bytes) {
		this.bytes = bytes;
	}

}
