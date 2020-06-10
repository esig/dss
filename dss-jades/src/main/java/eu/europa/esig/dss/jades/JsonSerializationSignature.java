package eu.europa.esig.dss.jades;

import java.util.Map;

public class JsonSerializationSignature {
	
	private String encodedProtected;
	
	private Map<String, Object> unprotected;
	
	private String encodedSignature;

	public String getEncodedProtected() {
		return encodedProtected;
	}

	public void setEncodedProtected(String encodedProtected) {
		this.encodedProtected = encodedProtected;
	}

	public Map<String, Object> getUnprotected() {
		return unprotected;
	}

	public void setUnprotected(Map<String, Object> unprotected) {
		this.unprotected = unprotected;
	}

	public String getEncodedSignature() {
		return encodedSignature;
	}

	public void setEncodedSignature(String encodedSignature) {
		this.encodedSignature = encodedSignature;
	}

}
