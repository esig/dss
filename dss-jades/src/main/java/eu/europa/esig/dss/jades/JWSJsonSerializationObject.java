package eu.europa.esig.dss.jades;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.utils.Utils;

public class JWSJsonSerializationObject {
	
	private String payload;
	
	private List<JsonSerializationSignature> signatures;
	
	private boolean flattened;

	public String getPayload() {
		if (payload == null) {
			payload = Utils.EMPTY_STRING;
		}
		return payload;
	}

	public void setPayload(String encodedPayload) {
		this.payload = encodedPayload;
	}

	public List<JsonSerializationSignature> getSignatures() {
		if (signatures == null) {
			signatures = new ArrayList<>();
		}
		return signatures;
	}

	public void setSignatures(List<JsonSerializationSignature> signatures) {
		this.signatures = signatures;
	}

	public boolean isFlattened() {
		return flattened;
	}

	public void setFlattened(boolean flattened) {
		this.flattened = flattened;
	}

}
