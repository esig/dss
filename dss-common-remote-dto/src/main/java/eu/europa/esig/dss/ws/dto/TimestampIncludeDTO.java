package eu.europa.esig.dss.ws.dto;

import java.io.Serializable;

public class TimestampIncludeDTO implements Serializable {
	
	private static final long serialVersionUID = -6910516846531402711L;
	
	private String uri;
	/* The referencedData attribute shall be present in each and every Include element, and set to "true". */
	private boolean referencedData;

	public TimestampIncludeDTO() {
	}

	public TimestampIncludeDTO(String uri, boolean referencedData) {
		this.uri = uri;
		this.referencedData = referencedData;
	}

	public String getURI() {
		return uri;
	}

	public void setURI(String uri) {
		this.uri = uri;
	}

	public boolean isReferencedData() {
		return referencedData;
	}

	public void setReferencedData(boolean referencedData) {
		this.referencedData = referencedData;
	}
}
