package eu.europa.esig.dss.jades;

import java.util.Map;

public class JsonSerializationSignature {
	
	private String base64UrlProtectedHeader;
	
	private Map<String, Object> unprotected;
	
	private String base64UrlSignature;

	public String getBase64UrlProtectedHeader() {
		return base64UrlProtectedHeader;
	}

	public void setBase64UrlProtectedHeader(String encodedProtected) {
		this.base64UrlProtectedHeader = encodedProtected;
	}

	public Map<String, Object> getUnprotected() {
		return unprotected;
	}

	public void setUnprotected(Map<String, Object> unprotected) {
		this.unprotected = unprotected;
	}

	public String getBase64UrlSignature() {
		return base64UrlSignature;
	}

	public void setBase64UrlSignature(String encodedSignature) {
		this.base64UrlSignature = encodedSignature;
	}

}
