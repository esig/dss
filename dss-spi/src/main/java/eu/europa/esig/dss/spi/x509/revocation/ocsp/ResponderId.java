package eu.europa.esig.dss.spi.x509.revocation.ocsp;

/**
 * OCSP Reference property
 */
public class ResponderId {
	
	private String name;
	
	private byte[] key;
	
	public String getName() {
		return name;
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public byte[] getKey() {
		return key;
	}
	
	public void setKey(byte[] key) {
		this.key = key;
	}
	
}
